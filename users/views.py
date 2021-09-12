from django.shortcuts import render, redirect
from django.contrib.auth import logout as do_logout
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login as do_login
from django.contrib.auth.forms import UserCreationForm
from .forms import CustomAuthForm

'''
View: register
Description: view whose function is to show a register user form
'''
def register(request):
    form = UserCreationForm()
    if request.method == "POST":
        form = UserCreationForm(data=request.POST)
        if form.is_valid():
            user = form.save()
            user.is_superuser = True
            user.is_staff = True
            user.is_admin = True
            if user is not None:
                do_login(request, user)
                return redirect('/')
    return render(request, "register.html", {'form': form})

'''
View: login
Description: view whose function is to show a log in form
'''
def login(request):
    form = AuthenticationForm()
    if request.method == "POST":
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(username=username, password=password)
            if user is not None:
                do_login(request, user)
                return redirect('/')
    return render(request, "login.html", {'form': form})

'''
View: logout
Description: view whose function is to log out an authenticathed user
'''
def logout(request):
    do_logout(request)
    return redirect('/')