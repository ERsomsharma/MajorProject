from django.urls import path
from . import views

urlpatterns =[
    path('place_order/', views.place_order, name='place_order'),
    path('payments/', views.payments, name='payments'),
    path('order_complete/', views.order_complete, name='order_complete'),
    path('order_detail/<int:order_id>/', views.order_detail, name='order_detail'),
    path('order_list/', views.order_list, name='order_list'),
    path('order_tracking/<str:order_number>/', views.order_tracking, name='order_tracking'),
    path('request_refund/', views.request_refund, name='request_refund'),
    path('request_cancellation/', views.request_cancellation, name='request_cancellation'),
    path('request_return/', views.request_return, name='request_return'),
]