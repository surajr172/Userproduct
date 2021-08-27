from numpy.core.fromnumeric import product
from .serializers import ProductSerializer
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework.generics import CreateAPIView
from rest_framework.generics import DestroyAPIView
from rest_framework.generics import UpdateAPIView
from product.models import Product
from rest_framework.response import Response
from rest_framework.views import APIView
from django.views import View
from django.http  import JsonResponse
import io
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser
from django.utils.decorators import method_decorator
from django.http import HttpResponse
from rest_framework.decorators import authentication_classes
from rest_framework.decorators import permission_classes
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework import status

import numpy as np
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import ListAPIView
from django_filters.rest_framework import DjangoFilterBackend

@api_view(['GET'])
@authentication_classes([ JWTAuthentication,])
@permission_classes([IsAuthenticated])
def productDetail(request, pk):
    try:
        products =Product.objects.get(id=pk)
        serializer = ProductSerializer(products, many = False)
        return Response(serializer.data)
    except Product.DoesNotExist:  
        return Response({'message': 'The product does not exist'}, status=status.HTTP_404_NOT_FOUND)   

@api_view(['POST'])
@authentication_classes([ JWTAuthentication,])
@permission_classes([IsAuthenticated])
def productCreate(request):
    data = {}
    serializer = ProductSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        data["massage"] = "Product created successfully."
        data["status"] = 200
        data["product"] = serializer.data
        return Response(data,status=status.HTTP_200_OK)
    return Response({"message" : serializer.errors,"status" : status.HTTP_404_NOT_FOUND})

@api_view(['PUT'])
@authentication_classes([ JWTAuthentication,])
@permission_classes([IsAuthenticated])
def productUpdate(request, pk):
    try:
        data = {}
        product = Product.objects.get(id = pk)
        serializer = ProductSerializer(instance=product, data=request.data)
        if serializer.is_valid():
            serializer.save()
            data["massage"] = "Product updated successfully."
            data["status"] = 201
            data["product"] = serializer.data
            return Response(data , status = status.HTTP_201_CREATED)
        return Response({"message" :serializer.errors , "status" : status.HTTP_400_BAD_REQUEST})
    except RuntimeError:
            return Response({'message': 'book not found', 'status': 400})

@api_view(['DELETE'])
@authentication_classes([ JWTAuthentication,])
@permission_classes([IsAuthenticated])
def productDelete(request, pk):
    product =Product.objects.get(id = pk)
    product.delete()
    return Response("product deleted successfully.")

    
# Create your views here.
# class ListProductAPIView(ListAPIView):
#     """This endpoint list all of the available products from the database"""
#     queryset = Product.objects.all()
#     serializer_class = ProductSerializer

#     def get_queryset(self):
#         return Product.objects.order_by('pprice')


# class CreateProductAPIView(CreateAPIView):
#     """This endpoint allows for creation of a product"""
#     queryset = Product.objects.all()
#     serializer_class = ProductSerializer

# class UpdateProductAPIView(UpdateAPIView):
#     """This endpoint allows for updating a specific product by passing in the id of the todo to update"""
#     queryset = Product.objects.all()
#     serializer_class = ProductSerializer

# class DeleteProductAPIView(DestroyAPIView):
#     """This endpoint allows for deletion of a specific Product from the database"""
#     queryset = Product.objects.all()
#     serializer_class = ProductSerializer