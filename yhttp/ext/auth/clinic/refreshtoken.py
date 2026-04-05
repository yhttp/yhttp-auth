

DEFAULT_SETTINGS = '''
  algorithm: HS256
  secret: '12345678901234567890123456789012'
  leeway: 10  # seconds
  maxage: 2592000  # 1 Month
  cookie:
    key: yhttp-refreshtoken
    secure: true
    httponly: true
    samesite: Strict
    domain:
    path:
'''
