from django.shortcuts import render

def index(request):
    return render(request, 'index.html')

def sign_in(request):
   hide_navbar = True
   return render(request, 'pages/sign-in.html', {'hide_navbar': hide_navbar})