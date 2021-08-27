from django.urls import path
from product import views

urlpatterns = [
    # path("",views.ListProductAPIView.as_view(),name="product_list"),
    # path("create/", views.CreateProductAPIView.as_view(),name="product_create"),
    # path("update/<int:pk>/",views.UpdateProductAPIView.as_view(),name="update_product"),
    # path("delete/<int:pk>/",views.DeleteProductAPIView.as_view(),name="delete_product")

    # path('book/', BookView.as_view()),
    #path('book/<int:pk>', BookDetailsView.as_view()),
    path('<int:pk>', views.productDetail, name="product-Detail"),
    path('', views.productCreate, name="product-Create"),
    path('update/<int:pk>', views.productUpdate, name="product-update"),
    path('delete/<int:pk>', views.productDelete, name="product-delete"),
]