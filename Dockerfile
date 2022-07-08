FROM python:3.9

ENV APP_HOME /sampleAppOAuth2
WORKDIR $APP_HOME
COPY . ./

RUN pip install -r requirements.txt
EXPOSE 8080

CMD ["python", "manage.py", "runserver", "0.0.0.0:8080"]
