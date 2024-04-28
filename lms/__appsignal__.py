import os
from openedx.core.djangoapps.site_configuration.models import SiteConfiguration

# Get APPSIGNAL_PUSH_API_KEY from environment
site = SiteConfiguration.objects.get(site__domain="thelearningalgorithm.ai")
APPSIGNAL_PUSH_API_KEY = os.environ.get("APPSIGNAL_PUSH_API_KEY")
os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

from appsignal import Appsignal
appsignal = Appsignal(
    active=True,
    name="openedx",
    push_api_key=APPSIGNAL_PUSH_API_KEY,
)