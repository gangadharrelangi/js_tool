# Patterns adapted from LinkFinder (Gerben Javado, MIT) and
# SecretFinder (m4ll0k, GPL-3.0). See NOTICE and licenses/.
import re

LINK_PATTERN = re.compile('\n\n  (?:"|\')                               # Start newline delimiter\n\n  (\n    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //\n    [^"\'/]{1,}\\.                        # Match a domainname (any character + dot)\n    [a-zA-Z]{2,}[^"\']{0,})              # The domainextension and/or path\n\n    |\n\n    ((?:/|\\.\\./|\\./)                    # Start with /,../,./\n    [^"\'><,;| *()(%%$^/\\\\\\[\\]]          # Next character can\'t be...\n    [^"\'><,;|()]{1,})                   # Rest of the characters can\'t be\n\n    |\n\n    ([a-zA-Z0-9_\\-/]{1,}/               # Relative endpoint with /\n    [a-zA-Z0-9_\\-/.]{1,}                # Resource name\n    \\.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)\n    (?:[\\?|#][^"|\']{0,}|))              # ? or # mark with parameters\n\n    |\n\n    ([a-zA-Z0-9_\\-/]{1,}/               # REST API (no extension) with /\n    [a-zA-Z0-9_\\-/]{3,}                 # Proper REST endpoints usually have 3+ chars\n    (?:[\\?|#][^"|\']{0,}|))              # ? or # mark with parameters\n\n    |\n\n    ([a-zA-Z0-9_\\-]{1,}                 # filename\n    \\.(?:php|asp|aspx|jsp|json|\n         action|html|js|txt|xml)        # . + extension\n    (?:[\\?|#][^"|\']{0,}|))              # ? or # mark with parameters\n\n  )\n\n  (?:"|\')                               # End newline delimiter\n\n', re.VERBOSE)
SECRET_PATTERNS = {'google_api': 'AIza[0-9A-Za-z-_]{35}',
 'firebase': 'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
 'google_captcha': '6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
 'google_oauth': 'ya29\\.[0-9A-Za-z\\-_]+',
 'amazon_aws_access_key_id': 'A[SK]IA[0-9A-Z]{16}',
 'amazon_mws_auth_toke': 'amzn\\\\.mws\\\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
 'amazon_aws_url': 's3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com',
 'amazon_aws_url2': '([a-zA-Z0-9-\\.\\_]+\\.s3\\.amazonaws\\.com|s3://[a-zA-Z0-9-\\.\\_]+|s3-[a-zA-Z0-9-\\.\\_\\/]+|s3.amazonaws.com/[a-zA-Z0-9-\\.\\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\\.\\_]+)',
 'facebook_access_token': 'EAACEdEose0cBA[0-9A-Za-z]+',
 'authorization_basic': 'basic [a-zA-Z0-9=:_\\+\\/-]{5,100}',
 'authorization_bearer': 'bearer [a-zA-Z0-9_\\-\\.=:_\\+\\/]{5,100}',
 'authorization_api': 'api[key|_key|\\s+]+[a-zA-Z0-9_\\-]{5,100}',
 'mailgun_api_key': 'key-[0-9a-zA-Z]{32}',
 'twilio_api_key': 'SK[0-9a-fA-F]{32}',
 'twilio_account_sid': 'AC[a-zA-Z0-9_\\-]{32}',
 'twilio_app_sid': 'AP[a-zA-Z0-9_\\-]{32}',
 'paypal_braintree_access_token': 'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}',
 'square_oauth_secret': 'sq0csp-[ '
                        '0-9A-Za-z\\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\\-_]{22,43}',
 'square_access_token': 'sqOatp-[0-9A-Za-z\\-_]{22}|EAAA[a-zA-Z0-9]{60}',
 'stripe_standard_api': 'sk_live_[0-9a-zA-Z]{24}',
 'stripe_restricted_api': 'rk_live_[0-9a-zA-Z]{24}',
 'github_access_token': '[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*',
 'rsa_private_key': '-----BEGIN RSA PRIVATE KEY-----',
 'ssh_dsa_private_key': '-----BEGIN DSA PRIVATE KEY-----',
 'ssh_dc_private_key': '-----BEGIN EC PRIVATE KEY-----',
 'pgp_private_block': '-----BEGIN PGP PRIVATE KEY BLOCK-----',
 'json_web_token': 'ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$',
 'slack_token': '\\"api_token\\":\\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\\"',
 'SSH_privKey': '([-]+BEGIN [^\\s]+ PRIVATE KEY[-]+[\\s]*[^-]*[-]+END [^\\s]+ '
                'PRIVATE KEY[-]+)',
 'Heroku API KEY': '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
 'possible_Creds': '(?i)(password\\s*[`=:\\"]+\\s*[^\\s]+|password '
                   'is\\s*[`=:\\"]*\\s*[^\\s]+|pwd\\s*[`=:\\"]*\\s*[^\\s]+|passwd\\s*[`=:\\"]+\\s*[^\\s]+)'}
