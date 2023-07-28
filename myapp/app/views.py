from django.shortcuts import render

def handling_404(request, exception):
   hide_navbar = True
   return render(request, 'pages/404.html', {'hide_navbar': hide_navbar})

def index(request):
    return render(request, 'index.html')

def sign_in(request):
   hide_navbar = True
   return render(request, 'pages/sign-in.html', {'hide_navbar': hide_navbar})