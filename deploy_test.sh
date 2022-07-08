gcloud builds submit --tag gcr.io/michael-gilbert-dev/oauth2app1.0.0 .;
gcloud run deploy --image=gcr.io/michael-gilbert-dev/oauth2app1.0.0 --platform managed --region us-central1;

