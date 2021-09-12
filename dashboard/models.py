from django.db import models

# Target model template
class target (models.Model):
    Url = models.CharField(max_length=255,default='')
    Domain = models.CharField(max_length=255)
    IPs = models.CharField(max_length=255)
