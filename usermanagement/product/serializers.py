from rest_framework import serializers
from .models import Product


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['id', 'name', 'pprice', 'category', 'description','account']
 
    def create(self, validated_data):
        return Product.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.pprice = validated_data.get('pprice', instance.pprice)
        instance.category = validated_data.get('category', instance.category)
        instance.description = validated_data.get('description', instance.description)   
        instance.account = validated_data.get('account', instance.account)
        
        instance.save()
        return instance

class GetProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['id', 'name', 'pprice', 'category', 'description','account']