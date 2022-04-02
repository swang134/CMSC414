import requests
import sys

# Session cookie should be in sys.argv[1]
# Argument should be session cookie itself, 
# not `session=...`
if len(sys.argv) < 2:
	print("Usage: python3 HTTPSimpleForge.py <session-cookie>")
	sys.exit(1)

# Update as needed
url = "http://now.share/update_profile"

headers = {
	'User-agent':'CMSC414-Forge',
	'Cookie': 'session = <session-cookie>',
	'Cookie':'session=' + sys.argv[1]
    # Complete
}

data = {
	'full_name': 'Alice Smith',
	'description': 'Bob is a l33t h4x0r!'
    # Complete
}

r = requests.post(url, timeout=(60000, 90000), data=data, headers=headers)
print(r.content)
