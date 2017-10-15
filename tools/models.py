# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models

# Create your models here.
class Tool(models.Model):
    title = models.CharField(max_length=200)
    text = models.TextField()
    keyword = models.CharField(max_length=30)

    def execute(self):
        return "test"

    def __str__(self):
        return self.title
