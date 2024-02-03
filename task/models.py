from django.db import models
from django.contrib.auth.models import User
from datetime import datetime
from simple_history.models import HistoricalRecords


class Task(models.Model):
    STATUS_CHOICES = [
        ('new', 'New'),
        ('ongoing', 'Ongoing'),
        ('finished', 'Finished'),
    ]

    title = models.CharField(max_length=50)
    description = models.TextField(blank=True)
    user = models.ForeignKey(User, blank=True, on_delete=models.DO_NOTHING)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='new')
    list_date = models.DateTimeField(default=datetime.now, blank=True)

    history = HistoricalRecords()

    def __str__(self):
        return self.title
