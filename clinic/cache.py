from datetime import timedelta
from time import sleep
from requests_cache import CachedSession

URL = 'https://www.googleapis.com/oauth2/v3/certs'
# URL = 'https://httpbin.org/delay/1'

# Create a session that respects Cache-Control headers
# session = CachedSession(
#     'http_cache',          # Name of the local database file
#     cache_control=True,    # Force the session to respect Cache-Control headers
#     expire_after=timedelta(days=1)  # Fallback expiration if the server provides no header
# )

session = CachedSession(
    'gsession',
    cache_control=True,
    always_revalidate=True,
    allowable_methods=['GET'],
    allowable_codes=[200],
    expire_after=timedelta(minutes=1),
)
# The first call fetches from the server; subsequent calls use the local cache
# according to the max-age directive in the server's Cache-Control header.
for i in range(130):
    response = session.get(URL)
    print(f'{i * 2}: from-cache: {response.from_cache}, expired: {response.is_expired}, {response.headers["Cache-Control"]}')
    sleep(2)
