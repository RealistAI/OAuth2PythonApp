import urllib
  
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseServerError
from django.conf import settings

def terms(request):
    return render(request, 'terms.html')

def privacy(request):
    return render(request, 'privacy.html')
