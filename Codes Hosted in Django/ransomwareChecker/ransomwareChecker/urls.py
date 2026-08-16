from django.urls import include, path
from file_app import views
urlpatterns = [
    path('', views.home),
    path('About.html', views.about),
    path('Solution.html', views.Solution),
    path('Program.html', views.programs),
]






