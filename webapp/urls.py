"""webapp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin

from django.urls import path
from users import views as views_user
from dashboard import views as views_dashboard
from users.forms import CustomAuthForm
from django.contrib.staticfiles.storage import staticfiles_storage
from django.views.generic.base import RedirectView

urlpatterns = [
    path('', views_dashboard.dashboard),
    path('register/', views_user.register),
    path('login/', views_user.login),
    path('logout/', views_user.logout),
    path('dashboard/', views_dashboard.dashboard),
    path('targets/', views_dashboard.targets),
    path('developer/', views_dashboard.developer),
    path('targets_remove/<int:id>', views_dashboard.targets_remove),
    path('targets_scan/<int:id>/<int:mode>', views_dashboard.targets_scan),
    path('reports/', views_dashboard.reports),
    path('reports_delete/<str:file>', views_dashboard.reports_delete),
    path('pdf_view/<str:file>', views_dashboard.pdf_view),
    path('admin/', admin.site.urls),
]
