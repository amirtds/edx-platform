from django.conf.urls import url

from lms.djangoapps.cubite_api import views


urlpatterns = [ 
    # user API
    url(r'^accounts/user_without_password', views.CreateUserAccountWithoutPasswordView.as_view(), name="create_user_account_without_password_api"),
    url(r'^accounts/create', views.CreateUserAccountView.as_view(), name="create_user_account_api"),
    url(r'^accounts/connect', views.UserAccountConnect.as_view(), name="user_account_connect_api"),
    url(r'^accounts/update_user', views.UpdateUserAccount.as_view(), name="user_account_update_user"),
    url(r'^accounts/get-user/(?P<username>[\w.+-]+)', views.GetUserAccountView.as_view(), name="get_user_account_api"),
    url(r'^accounts/deactivate_user', views.DeactivateUserAccount.as_view(), name="user_account_deactivate_user"),
    url(r'^accounts/activate_user', views.ActivateUserAccount.as_view(), name="user_account_activate_user"),

    # Just like CourseListView API, but with search
    url(r'^search_courses', views.CourseListSearchView.as_view(), name="course_list_search"),

    # bulk enrollment API
    url(r'^bulk-enrollment/bulk-enroll', views.BulkEnrollView.as_view(), name="bulk_enrollment_api"),

]
