import urllib

from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseServerError
from django.conf import settings

from RealistBRAIN import getDiscoveryDocument
from RealistBRAIN.services import (
    getCompanyInfo,
    getBearerTokenFromRefreshToken,
    getUserProfile,
    getBearerToken,
    getSecretKey,
    validateJWTToken,
    revokeToken,
    cache_refresh_token,
    cache_access_token,
    cache_realm_id,
    access_secret_version,
)

company_name = 'whitestone'
project_id = 'michael-gilbert-dev'


def index(request):
    return render(request, 'index.html')


def connectToQuickbooks(request):
    url = getDiscoveryDocument.auth_endpoint
    CLIENT_ID = access_secret_version(secret_id='brain_client_id')
    params = {'scope': settings.ACCOUNTING_SCOPE, 'redirect_uri': settings.REDIRECT_URI,
              'response_type': 'code', 'state': get_CSRF_token(request), 'client_id': CLIENT_ID}
    url += '?' + urllib.parse.urlencode(params)
    return redirect(url)


def signInWithIntuit(request):
    url = getDiscoveryDocument.auth_endpoint
    CLIENT_ID = access_secret_version(secret_id='brain_client_id')
    scope = ' '.join(settings.OPENID_SCOPES)  # Scopes are required to be sent delimited by a space
    params = {'scope': scope, 'redirect_uri': settings.REDIRECT_URI,
              'response_type': 'code', 'state': get_CSRF_token(request), 'client_id': CLIENT_ID}
    url += '?' + urllib.parse.urlencode(params)
    return redirect(url)


def getAppNow(request):
    url = getDiscoveryDocument.auth_endpoint
    CLIENT_ID = access_secret_version(secret_id='brain_client_id')
    scope = ' '.join(settings.GET_APP_SCOPES)  # Scopes are required to be sent delimited by a space
    params = {'scope': scope, 'redirect_uri': settings.REDIRECT_URI,
              'response_type': 'code', 'state': get_CSRF_token(request), 'client_id': CLIENT_ID}
    url += '?' + urllib.parse.urlencode(params)
    return redirect(url)


def authCodeHandler(request):
    state = request.GET.get('state', None)
    error = request.GET.get('error', None)
    if error == 'access_denied':
        return redirect('RealistBRAIN:index')
    if state is None:
        return HttpResponseBadRequest()
    elif state != get_CSRF_token(request):  # validate against CSRF attacks
        return HttpResponse('unauthorized', status=401)

    auth_code = request.GET.get('code', None)
    if auth_code is None:
        return HttpResponseBadRequest()

    bearer = getBearerToken(auth_code)
    realmId = request.GET.get('realmId', None)
    cache_refresh_token(refresh_token=bearer.refreshToken)
    cache_access_token(access_token=bearer.accessToken)
    cache_realm_id(realm_id=realmId)
    updateSession(request, bearer.accessToken, bearer.refreshToken, realmId)

    # Validate JWT tokens only for OpenID scope
    if bearer.idToken is not None:
        if not validateJWTToken(bearer.idToken):
            return HttpResponse('JWT Validation failed. Please try signing in again.')
        else:
            return redirect('RealistBRAIN:connected')
    else:
        return redirect('RealistBRAIN:connected')


def connected(request):
    access_token = request.session.get('accessToken', None)
    if access_token is None:
        return HttpResponse('Your Bearer token has expired, please initiate Sign In With Intuit flow again')

    refresh_token = request.session.get('refreshToken', None)
    realmId = request.session['realmId']
    if realmId is None:
        user_profile_response, status_code = getUserProfile(access_token)

        if status_code >= 400:
            # if call to User Profile Service doesn't succeed then get a new bearer token from refresh token
            # and try again
            bearer = getBearerTokenFromRefreshToken(refresh_token)
            cache_refresh_token(refresh_token=bearer.refreshToken)
            cache_access_token(access_token=bearer.accessToken)
            user_profile_response, status_code = getUserProfile(bearer.accessToken)
            updateSession(request, bearer.accessToken, bearer.refreshToken, request.session.get('realmId', None),
                          name=user_profile_response.get('givenName', None))

            if status_code >= 400:
                return HttpResponseServerError()
        c = {
            'first_name': user_profile_response.get('givenName', ' '),
        }
    else:
        if request.session.get('name') is None:
            name = ''
        else:
            name = request.session.get('name')
        c = {
            'first_name': name,
        }

    cache_realm_id(realm_id=realmId)
    return render(request, 'connected.html', context=c)


def disconnect(request):
    access_token = request.session.get('accessToken', None)
    refresh_token = request.session.get('refreshToken', None)

    revoke_response = ''
    if access_token is not None:
        revoke_response = revokeToken(access_token)
    elif refresh_token is not None:
        revoke_response = revokeToken(refresh_token)
    else:
        return HttpResponse('No accessToken or refreshToken found, Please connect again')

    request.session.flush()
    return HttpResponse(revoke_response)

def revoke_token(request):
    return render(request, 'revoke_token.html')

def access_revoked(request):
    return render(request, 'access_revoked.html')

def refreshTokenCall(request):
    refresh_token = request.session.get('refreshToken', None)
    if refresh_token is None:
        return HttpResponse('Not authorized')
    bearer = getBearerTokenFromRefreshToken(refresh_token)
    cache_refresh_token(refresh_token=bearer.refreshToken)
    cache_access_token(access_token=bearer.accessToken)
    if isinstance(bearer, str):
        return HttpResponse(bearer)
    else:
        return HttpResponse('Access Token: ' + bearer.accessToken + ', Refresh Token: ' + bearer.refreshToken)
    


def apiCall(request):
    access_token = request.session.get('accessToken', None)
    if access_token is None:
        return HttpResponse('Your Bearer token has expired, please initiate C2QB flow again')

    realmId = request.session['realmId']
    if realmId is None:
        return HttpResponse('No realm ID. QBO calls only work if the accounting scope was passed!')
    cache_realm_id(realm_id=realmId)
    refresh_token = request.session['refreshToken']
    company_info_response, status_code = getCompanyInfo(access_token, realmId)
    
    if status_code >= 400:
        # if call to QBO doesn't succeed then get a new bearer token from refresh token and try again
        bearer = getBearerTokenFromRefreshToken(refresh_token)
        updateSession(request, bearer.accessToken, bearer.refreshToken, realmId)
        cache_refresh_token(refresh_token=bearer.refreshToken)
        cache_access_token(access_token=bearer.accessToken)
        company_info_response, status_code = getCompanyInfo(bearer.accessToken, realmId)
        if status_code >= 400:
            return HttpResponseServerError()
    company_name = company_info_response['CompanyInfo']['CompanyName']
    address = company_info_response['CompanyInfo']['CompanyAddr']
    return HttpResponse('Company Name: ' + company_name + ', Company Address: ' + address['Line1'] + ', ' + address[
        'City'] + ', ' + ' ' + address['PostalCode'])


def get_CSRF_token(request):
    token = request.session.get('csrfToken', None)
    if token is None:
        token = getSecretKey()
        request.session['csrfToken'] = token
    return token


def updateSession(request, access_token, refresh_token, realmId, name=None):
    request.session['accessToken'] = access_token
    request.session['refreshToken'] = refresh_token
    request.session['realmId'] = realmId
    request.session['name'] = name
