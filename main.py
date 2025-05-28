import requests
import sys
import threading
import base64
import tls_client
import time
import uuid
import json
import random
from logg import CustomLogger
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from colorama import Fore, init

Log = CustomLogger()
thread_lock = threading.Lock()
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
request_exceptions = (requests.exceptions.ProxyError,
                      requests.exceptions.Timeout,
                      requests.exceptions.SSLError)


class Utils:
    # Remove a line from a file
    @staticmethod
    def remove_content(filename: str, delete_line: str) -> None:
        with thread_lock, open(filename, "r+") as file:
            lines = file.readlines()
            file.seek(0)
            file.writelines(line for line in lines if delete_line not in line)
            file.truncate()


class DeviceToken:

    # Used for `sig` header
    @staticmethod
    def sign(http_method: str, uri_path: str, payload: str,
             priv_key: ec.EllipticCurvePrivateKey) -> str:
        # windows timestamp
        win_time = (int(time.time()) + 11644473600) * 10000000
        data = b''
        data += b"\0\0\0\1\0"
        data += win_time.to_bytes(8, "big") + b'\0'
        data += http_method.encode() + b'\0'
        data += uri_path.encode() + b'\0'
        data += b'\0'
        data += payload.encode() + b'\0'

        sig = priv_key.sign(data, ec.ECDSA(hashes.SHA256()))
        (r, s) = decode_dss_signature(sig)
        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder="big")
        s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")

        raw_sig = b'\0\0\0\1' + win_time.to_bytes(8, "big") + r_bytes + s_bytes
        sig = base64.b64encode(raw_sig).decode("ascii")
        return sig

    # Generate proof key data
    @staticmethod
    def get_proofkey(priv_key: ec.EllipticCurvePrivateKey):

        def int_to_base64(x: int, length=32, byteorder='big') -> str:
            return base64.urlsafe_b64encode(x.to_bytes(
                length, byteorder)).decode("ascii").replace('=', '')

        return dict(
            alg="ES256",
            crv="P-256",
            kty="EC",
            use="sig",
            x=int_to_base64(priv_key.private_numbers().public_numbers.x),
            y=int_to_base64(priv_key.private_numbers().public_numbers.y))

    # Generate SECP256R1 key
    @staticmethod
    def get_device_key() -> ec.EllipticCurvePrivateKey:
        priv_key = ec.generate_private_key(ec.SECP256R1())
        priv_key_pem = priv_key.private_bytes(Encoding.PEM,
                                              PrivateFormat.PKCS8,
                                              NoEncryption())
        return priv_key

    # Get device token string
    @staticmethod
    def get_device_token() -> str:

        priv_key: ec.EllipticCurvePrivateKey = DeviceToken.get_device_key()
        # yapf: disable
        payload_obj = dict(
            Properties=dict(
                AuthMethod="ProofOfPossession",
                DeviceType="Win32",
                Id="{" + str(uuid.uuid4()).upper() + "}",
                ProofKey=DeviceToken.get_proofkey(priv_key),
            ),
            RelyingParty="http://auth.xboxlive.com",
            TokenType="JWT"
        )

        payload = json.dumps(payload_obj, indent=2)
        target = 'https://device.auth.xboxlive.com/device/authenticate'
        sig = DeviceToken.sign("POST", '/device/authenticate', payload, priv_key)

        session = tls_client.Session(client_identifier="chrome_108")
        while True:
            try:
                response = session.post(target,json=payload,headers={
                                           "Content-Type": "application/json",
                                           "x-xbl-contract-version": "1",
                                           "Signature": sig
                                       })
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                else:
                    Log.error(str(e),"r")
                    return
        return response.json()['Token']

def main(ms_creds : str):
    # Validate and clean the credential string
    ms_creds = ms_creds.strip()

    # Check if credentials are empty or invalid
    if not ms_creds:
        Log.error("Empty credential string provided", "r")
        return

    # Parse credentials based on delimiter
    if "|" in ms_creds:
        cred_parts = ms_creds.split('|')
        if len(cred_parts) < 2:
            Log.error(f"Invalid credential format (missing password after |): {ms_creds}", "r")
            return
        email = cred_parts[0].strip()
        pswd = cred_parts[1].strip()
    elif ":" in ms_creds:
        cred_parts = ms_creds.split(':')
        if len(cred_parts) < 2:
            Log.error(f"Invalid credential format (missing password after :): {ms_creds}", "r")
            return
        email = cred_parts[0].strip()
        pswd = cred_parts[1].strip()
    else:
        Log.error(f"Invalid credential format (no delimiter found): {ms_creds}", "r")
        return

    # Validate email and password are not empty
    if not email or not pswd:
        Log.error(f"Invalid credentials (empty email or password): {ms_creds}", "r")
        return
    Log.info(f"Using {email}")
    s = requests.session()
    try:
        proxies = {'https':'http://'+random.choice(open('proxies.txt').read().splitlines())}
    except:
        proxies = None
    s.proxies = proxies
    headers = {
     'Accept':
     'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
     'Accept-Language': 'en-US,en;q=0.9',
     'Connection': 'keep-alive',
     'Sec-Fetch-Dest': 'document',
     'Accept-Encoding': 'identity',
     'Sec-Fetch-Mode': 'navigate',
     'Sec-Fetch-Site': 'none',
     'Sec-Fetch-User': '?1',
     'Sec-GPC': '1',
     'Upgrade-Insecure-Requests': '1',
     'User-Agent': ua,
    }

    while True:
        try:
            response = s.get('https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F&scope=service::user.auth.xboxlive.com::MBI_SSL&response_type=token&redirect_uri=https://login.live.com/oauth20_desktop.srf',
                             headers=headers,
                             timeout=20).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            Log.error(str(e), "r")
            return
    try:
        ppft = response.split(
         ''''<input type="hidden" name="PPFT" id="i0327" value="''')[1].split('"')[0]
        log_url = response.split(",urlPost:'")[1].split("'")[0]
    except:
        Log.error(" Unknown Error (Proxies probably banned)")
        return
    log_data = f'i13=0&login={email}&loginfmt={email}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={pswd}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i19=449894'
    headers = {
     'Accept':
     'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
     'Accept-Language': 'en-US,en;q=0.9',
     'Cache-Control': 'max-age=0',
     'Connection': 'keep-alive',
     'Content-Type': 'application/x-www-form-urlencoded',
     'Origin': 'https://login.live.com',
     'Referer': 'https://login.live.com/',
     'Sec-Fetch-Dest': 'document',
     'Sec-Fetch-Mode': 'navigate',
     'Sec-Fetch-Site': 'same-origin',
     'Sec-Fetch-User': '?1',
     'Sec-GPC': '1',
     'Upgrade-Insecure-Requests': '1',
     'User-Agent': ua,
    }
    while True:
        try:
            response = s.post(log_url, timeout=20, data=log_data, headers=headers)
            break
        except request_exceptions:
            continue
        except Exception as e:
            Log.error(e, "r")
            return
    if 'https://account.live.com/proofs/Add' in response.text:
        headers = {
        'authority': 'account.live.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://login.live.com',
        'referer': 'https://login.live.com/',
        'sec-ch-ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-site',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        }
        ipt = response.text.split('id="ipt" value="')[1].split('"')[0]
        pprid = response.text.split('id="pprid" value="')[1].split('"')[0]
        uaid = response.text.split('id="uaid" value="')[1].split('"')[0]
        data = f'ipt={ipt}&pprid={pprid}&uaid={uaid}'
        fmHf = response.text.split('id="fmHF" action="')[1].split('"')[0]

        while True:
            try:
                response = s.post(fmHf,data=data,headers=headers)
                break
            except:
                continue
        headers = {
        'authority': 'account.live.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.8',
        'cache-control': 'max-age=0',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.live.com',
        'referer': response.url,
        'sec-ch-ua': '"Chromium";v="112", "Brave";v="112", "Not:A-Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'sec-gpc': '1',
        'upgrade-insecure-requests': '1',
        'user-agent': ua,
        }


        data = {
        'iProofOptions': 'Email',
        'DisplayPhoneCountryISO': 'US',
        'DisplayPhoneNumber': '',
        'EmailAddress': '',
        'canary': response.text.split('id="canary" name="canary" value="')[1].split('"')[0],
        'action': 'Skip',
        'PhoneNumber': '',
        'PhoneCountryISO': '',
        }

        while True:
            try:
                response = s.post(response.text.split('id="frmAddProof" method="post" action="')[1].split('"')[0], headers=headers, data=data)
                break
            except request_exceptions:
                continue
            except Exception as e:
                Log.error(str(e),'r')
                return
    try:
        rpsTicket = response.url.split('access_token=')[1].split('&')[0]
    except:
        Log.error('Invalid Account Credentials','')
        Utils.remove_content('accs.txt',ms_creds)
        return

    headers = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.7',
    'Connection': 'keep-alive',
    'Origin': 'https://www.xbox.com',
    'Referer': 'https://www.xbox.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-GPC': '1',
    'User-Agent': ua,
    'content-type': 'application/json',
    'ms-cv': '6XHlfdK3HMhZEz8LfxSLAl.12',
    'sec-ch-ua': '"Chromium";v="112", "Brave";v="112", "Not:A-Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'x-xbl-contract-version': '1',
    }

    json_data = {
    'Properties': {
        'AuthMethod': 'RPS',
        'RpsTicket': rpsTicket,
        'SiteName': 'user.auth.xboxlive.com',
    },
    'RelyingParty': 'http://auth.xboxlive.com',
    'TokenType': 'JWT',
    }
    while True:
        try:
            response = s.post('https://user.auth.xboxlive.com/user/authenticate', headers=headers, json=json_data)
            break
        except request_exceptions:continue
        except Exception as e:
            Log.error(str(e),'r')
            return

    userToken = response.json()['Token']
    while True:
        try:
            deviceToken = DeviceToken.get_device_token()
            break
        except:
            continue
    headers = {
    'authority': 'xsts.auth.xboxlive.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.7',
    'content-type': 'application/json',
    'ms-cv': 'u9Vh9cnctxQKKt3hYD1o37.22',
    'origin': 'https://www.xbox.com',
    'referer': 'https://www.xbox.com/',
    'sec-ch-ua': '"Chromium";v="112", "Brave";v="112", "Not:A-Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'sec-gpc': '1',
    'user-agent': ua,
    'x-xbl-contract-version': '1',
    }

    json_data = {
    'Properties': {
        'SandboxId': 'RETAIL',
        'UserTokens': [
            userToken,
        ],
        'DeviceToken' : deviceToken
    },
    'RelyingParty': 'http://xboxlive.com',
    'TokenType': 'JWT',
    }

    while True:
        try:
            response = s.post('https://xsts.auth.xboxlive.com/xsts/authorize', headers=headers, json=json_data)
            break
        except:
            continue

    xsts = response.json()['Token']
    uhs = response.json()['DisplayClaims']['xui'][0]['uhs']
    xbl = f"XBL3.0 x={uhs};{xsts}"

    while True:
        try:
            response =  requests.post("https://profile.gamepass.com/v2/offers/A3525E6D4370403B9763BCFA97D383D9/",headers={'authorization':xbl},proxies=proxies)
            break
        except:
            continue

    if "resource" in response.json():
        link = response.json()['resource']
    else:
        Log.error(f' Failed to get promo! text : {response.text} code : {response.status_code}', 'y')
        if "ineligible" in response.text:
            Utils.remove_content('accs.txt', ms_creds)
        return


    Log.promo(f'Successfully Fetched | {Fore.BLACK}{link} | {Fore.RESET} {email}:{pswd}"', '')
    Utils.remove_content('accs.txt',ms_creds)
    open('promos.txt','a').write(link+'\n')
init()
# Read and filter accounts, removing empty lines and whitespace-only lines
accs = [line.strip() for line in open('accs.txt').read().splitlines() if line.strip()]
Log.info("Made by anomusly, If any issues dm me anomus.ly.. Hope you like the tool.")

# Check if there are any valid accounts to process
if not accs:
    Log.error("No valid accounts found in accs.txt. Please add accounts in format 'email:password' or 'email|password'", "r")
    input("Press Enter to exit...")
    sys.exit(1)

Log.info(f"Loaded {len(accs)} accounts from accs.txt")
thread_amt = int(input(Fore.LIGHTBLUE_EX + 'Enter amount of threads : '))
thread_list = []
if __name__ == "__main__":
    while len(accs) > 0:
        try:
            local_threads = []
            for x in range(thread_amt):
                # Check if there are still accounts to process
                if len(accs) == 0:
                    break
                email = accs[0]
                start_thread = threading.Thread(target=main, args=(email,))
                local_threads.append(start_thread)
                start_thread.start()
                try:
                    accs.pop(0)
                except:
                    pass
            for thread in local_threads:
                thread.join()
        except IndexError:
            break
        except:
            pass
