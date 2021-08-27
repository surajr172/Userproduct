from account.models import Account
from django.db import models
LANGUAGE_CHOICES = (
    ('Mobile' , 'Mobile'),
    ('Appliances', 'Appliances'),
    ('Sports' , 'Sports'),
    ('Fashion' , 'Fashion'),
    ('Beauty' , 'Beauty'),
)
# Create your models here.

class Product(models.Model):
    account = models.ForeignKey(
    Account, on_delete=models.SET_NULL, null=True)
    name = models.CharField(max_length = 20)
    pprice = models.IntegerField(blank= False,default='0')
    category= models.CharField(choices=LANGUAGE_CHOICES, default='-----', max_length=100)
    description = models.CharField(max_length=50)

    def __str___(self):
        return self.name