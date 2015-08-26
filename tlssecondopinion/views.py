from django.http import HttpResponseRedirect, HttpResponse
from django.views.generic import View

def index(request):
    return HttpResponseRedirect('scan')
