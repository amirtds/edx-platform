"""
Tests for the Welovebit API views.
"""

import json
import pytz
import ddt

from urllib import quote, urlencode
from datetime import datetime
from mock import patch
from rest_framework.permissions import AllowAny
from rest_framework.test import APIRequestFactory

from django.core.urlresolvers import reverse
from django.test.utils import override_settings

from lms.djangoapps.course_api.tests.test_views import CourseApiTestViewMixin
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from search.tests.tests import TEST_INDEX_NAME
from search.tests.test_course_discovery import DemoCourse
from search.tests.utils import SearcherMixin

from student.tests.factories import CourseEnrollmentFactory
from xmodule.modulestore.tests.factories import CourseFactory
from certificates.models import GeneratedCertificate
from opaque_keys.edx.keys import CourseKey


# Any class that inherits from TestCase will cause too-many-public-methods pylint error
# pylint: disable=too-many-public-methods
@override_settings(ELASTIC_FIELD_MAPPINGS={  # pylint: disable=too-many-ancestors
    "start_date": {"type": "date"},
    "enrollment_start": {"type": "date"},
    "enrollment_end": {"type": "date"}
})
@override_settings(SEARCH_ENGINE="search.tests.mock_search_engine.MockSearchEngine")
@override_settings(COURSEWARE_INDEX_NAME=TEST_INDEX_NAME)
class CourseListSearchViewTest(CourseApiTestViewMixin, ModuleStoreTestCase, SearcherMixin):
    """
    Similar to search.tests.test_course_discovery_views but with the course API integration.
    """

    def setUp(self):
        super(CourseListSearchViewTest, self).setUp()
        DemoCourse.reset_count()
        self.searcher.destroy()

        self.courses = [
            self.add_course("OrgA", "Find this one with the right parameter"),
            self.add_course("OrgB", "Find this one with another parameter"),
            self.add_course("OrgC", "Find this one somehow"),
        ]

        self.url = reverse('course-list')
        self.staff_user = self.create_user(username='staff', is_staff=True)
        self.honor_user = self.create_user(username='honor', is_staff=False)

    def add_course(self, org_code, short_description):
        """
        Add a course to both database and search.

        Warning: A ton of gluing here! If this fails, double check both CourseListViewTestCase and MockSearchUrlTest.
        """

        search_course = DemoCourse.get({
            "org": org_code,
            "run": "2010",
            "number": "DemoZ",
            "id": "{org_code}/DemoZ/2010".format(org_code=org_code),
            "content": {
                "short_description": short_description,
            },
        })

        DemoCourse.index(self.searcher, [search_course])

        org, course, run = search_course['id'].split('/')

        db_course = self.create_course(
            org=org,
            course=course,
            run=run,
            short_description=short_description,
        )

        return db_course

    def search_request(self, search_term=''):
        res = self.client.get(reverse("course_list_search"), data={'search_term': search_term})
        return res.status_code, json.loads(res.content)

    def test_search_api_alone(self):
        """
        Double check that search alone works fine.
        """
        res = self.client.post(reverse('course_discovery'))
        data = json.loads(res.content)
        self.assertNotEqual(data["results"], [])
        self.assertNotIn('course-v1', unicode(self.courses[0].id))
        self.assertContains(res, unicode(self.courses[0].id))
        self.assertEqual(data["total"], 3)

    def test_course_api_alone(self):
        """
        Double check that search alone works fine.
        """
        self.setup_user(self.staff_user)
        response = self.verify_response(expected_status_code=200, params={'username': self.staff_user.username})
        data = json.loads(response.content)
        self.assertNotEqual(data["results"], [])
        self.assertEqual(data["pagination"]["count"], 3)
        self.assertNotIn('course-v1', response.content)

    def test_list_all(self):
        """ test searching using the url """
        code, data = self.search_request()
        self.assertEqual(200, code)
        self.assertIn("results", data)
        self.assertNotEqual(data["results"], [])
        self.assertEqual(data["pagination"]["count"], 3)

    def test_list_all_with_search_term(self):
        """ test searching using the url """
        code, data = self.search_request(search_term='somehow')
        self.assertEqual(200, code)
        self.assertIn("results", data)
        self.assertNotEqual(data["results"], [])
        self.assertEqual(data["pagination"]["count"], 1)


@ddt.ddt
@patch('welovebit_api.views.GetBatchCompletionDataView.authentication_classes', [])
@patch('welovebit_api.views.GetBatchCompletionDataView.permission_classes', [AllowAny])
class GetBatchCompletionDataViewTest(CourseApiTestViewMixin, ModuleStoreTestCase):
    """
    Tests for GetBatchCompletionDataView
    """
    def setUp(self):
        super(GetBatchCompletionDataViewTest, self).setUp()

        self.course1 = CourseFactory()
        self.course2 = CourseFactory()

        test_time = datetime(year=1999, month=1, day=1, minute=0, second=0, tzinfo=pytz.UTC)

        # Create sample enrollments at 2000, 2010 and 2020 years
        self.enrollments = [
            CourseEnrollmentFactory(course_id=self.course1.id),
            CourseEnrollmentFactory(course_id=self.course1.id),
            CourseEnrollmentFactory(course_id=self.course1.id),
            CourseEnrollmentFactory(course_id=self.course2.id),
        ]

        for ce in self.enrollments:
            GeneratedCertificate(
                course_id=ce.course_id,
                user=ce.user,
            ).save()

        self.certificates = list(GeneratedCertificate.objects.all())

        # certificate issue dates at years 2005, 2015, 2025 (five years after each enrollment)
        #   Likewise, these values need to be updated after GeneratedCertificates are saved to db
        years = [
            {'enrollment': 2000, 'certificate': 2005},
            {'enrollment': 2010, 'certificate': 2015},
            {'enrollment': 2020, 'certificate': 2025},
            {'enrollment': 2020, 'certificate': 2025},
        ]
        for enrollment, certificate, year in zip(self.enrollments, self.certificates, years):
            enrollment.created = test_time.replace(year=year['enrollment'])
            enrollment.save()
            certificate.created_date = test_time.replace(year=year['certificate'])
            certificate.save()

        self.url = reverse('get_batch_completion_data')

    def _create_cert_without_matching_course(self):
        # Create a GeneratedCertificate object for a course that no longer exists
        #   and return str(deleted_course_id)

        deleted_course_id_string = 'course-v1:edX+Deleted_course+1990'
        deleted_course_id = CourseKey.from_string(deleted_course_id_string)
        gc = GeneratedCertificate(course_id=deleted_course_id, user=self.enrollments[0].user)
        gc.save()

        return deleted_course_id_string

    def test_analytics_enrollment_endpoint_alone(self):

        res = self.client.get(self.url)

        self.assertIn('completion_date', res.content)
        self.assertEqual(res.status_code, 200)

        data = res.data
        self.assertEqual(len(data), len(self.certificates))

    @ddt.unpack
    @ddt.data({'query_string': 'updated_min=2030-01-01T00:00:00', 'num_certificates': 0},
              {'query_string': 'updated_min=2010-01-01T00:00:00', 'num_certificates': 3},
              {'query_string': 'updated_max=2010-01-01T00:00:00', 'num_certificates': 1},
              {'query_string': 'updated_min=2010-01-01T00:00:00&updated_max=2020-01-01T00:00:00', 'num_certificates': 1},)
    def test_analytics_enrollment_endpoint_with_query_strings(self, query_string, num_certificates):

        res = self.client.get(self.url + '?{}'.format(query_string))

        if num_certificates > 0:
            self.assertIn('completion_date', res.content)
        self.assertEqual(res.status_code, 200)

        data = res.data
        print query_string
        print data
        self.assertEqual(len(data), num_certificates)

    def test_certificate_without_course(self):
        # Test the codepath for a certificate requested about a previously deleted course
        # The course_name and
        deleted_course_id_string = self._create_cert_without_matching_course()

        res = self.client.get(self.url)

        self.assertIn('completion_date', res.content)
        self.assertEqual(res.status_code, 200)

        data = res.data

        cert_with_missing_course_list = [
            cert for cert in data
            if cert['course_id'] == deleted_course_id_string
        ]

        self.assertEqual(len(cert_with_missing_course_list), 1)
        cert_with_missing_course = cert_with_missing_course_list[0]

        self.assertEqual(cert_with_missing_course['course_name'],
                         cert_with_missing_course['course_id'],
                         'course_name and course_id should be equal if course does\'t exist on server')
