from django.contrib import admin
from .models import Payment, Order, OrderProduct

# Register your models here.

class OrderProductInline(admin.TabularInline):
    model = OrderProduct
    readonly_fields = ('payment', 'user', 'product', 'variations', 'quantity', 'product_price', 'ordered')
    extra = 0

class PaymentAdmin(admin.ModelAdmin):
    list_display = ('payment_id', 'user', 'amount_paid', 'status', 'created_at')
    search_fields = ('payment_id', 'user__username', 'status')
    list_filter = ('status', 'created_at')
admin.site.register(Payment, PaymentAdmin)

class OrderAdmin(admin.ModelAdmin):
    list_display = ('order_number', 'full_name', 'phone', 'email', 'order_total', 'tax', 'status', 'is_ordered', 'created_at')
    search_fields = ('order_number','status', 'is_ordered', 'user__username', 'first_name', 'last_name', 'phone', 'email') 
    list_filter = ('status', 'is_ordered', 'created_at')
    list_per_page = 20
    inlines = [OrderProductInline]
admin.site.register(Order, OrderAdmin)  

class OrderProductAdmin(admin.ModelAdmin):
    list_display = ('order', 'product', 'user', 'quantity', 'product_price', 'ordered', 'created_at')
    search_fields = ('order__order_number', 'product__name', 'user__username')
    list_filter = ('ordered', 'created_at')
admin.site.register(OrderProduct, OrderProductAdmin)

