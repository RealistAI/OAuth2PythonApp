echo "The access token is:";
gcloud secrets versions access latest --secret="best_company_access_token";
echo
echo "The refresh token is:";
gcloud secrets versions access latest --secret="best_company_refresh_token"
echo
