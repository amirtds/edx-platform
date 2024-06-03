import os



# Get APPSIGNAL_PUSH_API_KEY from environment
push_api_key = os.getenv('APPSIGNAL_PUSH_API_KEY')
os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

from appsignal import Appsignal                   
appsignal = Appsignal(
    active=True,
    name="openedx",
    push_api_key=push_api_key,
)