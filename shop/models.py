from django.db import models
from django.contrib.auth.models import AbstractUser


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    birth_date = models.DateField(null=True, blank=True)
    additional_field = models.CharField(max_length=100, blank=True, null=True)
    bio = models.TextField(null=True, blank=True)
    title = models.CharField(max_length=100, default="Без титула")
    def __str__(self):
        return self.username

    
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True, null=True)
    first_name = models.CharField(max_length=30, blank=True, null=True)
    last_name = models.CharField(max_length=30, blank=True, null=True)
    birth_date = models.DateField(blank=True, null=True)
    headline = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"
    

class Description(models.Model):
    text = models.TextField(default="Это описание, которое можно изменить.")

    def __str__(self):
        return self.text
