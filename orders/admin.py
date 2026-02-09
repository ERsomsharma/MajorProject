from django.contrib import admin
from .models import Payment, Order, OrderProduct, OrderTracking
from .views import send_refund_decision_email, send_cancellation_decision_email

# Register your models here.

class OrderProductInline(admin.TabularInline):
    model = OrderProduct
    readonly_fields = ('payment', 'user', 'product', 'variations', 'quantity', 'product_price', 'ordered')
    extra = 0

class OrderTrackingInline(admin.TabularInline):
    model = OrderTracking
    extra = 1
    fields = ('status', 'description', 'location', 'timestamp')
    readonly_fields = ('timestamp',)

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
    inlines = [OrderProductInline, OrderTrackingInline]
    
    def mark_as_accepted(self, request, queryset):
        """Mark orders as Accepted and create tracking"""
        for order in queryset:
            order.status = 'Accepted'
            order.save()
            
            # Create tracking if not exists
            if not order.tracking_history.filter(status='Processing').exists():
                OrderTracking.objects.create(
                    order=order,
                    status='Processing',
                    description='Your order is being processed and packed for shipment.',
                    location='Fulfillment Center'
                )
        
        self.message_user(request, f"{queryset.count()} orders marked as Accepted")
    
    mark_as_accepted.short_description = "Mark selected orders as Accepted (Processing)"
    
    def mark_as_completed(self, request, queryset):
        """Mark orders as Completed and create tracking"""
        for order in queryset:
            order.status = 'Completed'
            order.save()
            
            # Create tracking if not exists
            if not order.tracking_history.filter(status='Delivered').exists():
                OrderTracking.objects.create(
                    order=order,
                    status='Delivered',
                    description='Your order has been delivered successfully.',
                    location=f'{order.city}, {order.state}'
                )
        
        self.message_user(request, f"{queryset.count()} orders marked as Completed")
    
    mark_as_completed.short_description = "Mark selected orders as Completed (Delivered)"
    
    actions = ['mark_as_accepted', 'mark_as_completed']

admin.site.register(Order, OrderAdmin)  

class OrderProductAdmin(admin.ModelAdmin):
    list_display = ('order', 'product', 'user', 'quantity', 'product_price', 'refund_status', 'cancellation_status', 'return_status', 'ordered', 'created_at')
    search_fields = ('order__order_number', 'product__name', 'user__username')
    list_filter = ('ordered', 'refund_status', 'cancellation_status', 'return_status', 'created_at')
    readonly_fields = ('refund_requested_at', 'cancellation_requested_at', 'return_requested_at', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('order', 'product', 'user', 'quantity', 'product_price', 'ordered')
        }),
        ('Refund Information', {
            'fields': ('refund_status', 'refund_reason', 'refund_requested_at'),
            'classes': ('collapse',)
        }),
        ('Cancellation Information', {
            'fields': ('cancellation_status', 'cancellation_reason', 'cancellation_requested_at'),
            'classes': ('collapse',)
        }),
        ('Return Information', {
            'fields': ('return_status', 'return_reason', 'return_requested_at'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def approve_refund(self, request, queryset):
        """Approve refund requests and send decision email"""
        count = 0
        for product in queryset:
            if product.refund_status == 'Requested':
                product.refund_status = 'Approved'
                product.save()
                OrderTracking.objects.create(
                    order=product.order,
                    status='Refund Approved',
                    description=f'Refund approved for {product.product.product_name}.',
                    location=''
                )
                # Send approval email to customer
                send_refund_decision_email(product, product.user, approved=True)
                count += 1
        self.message_user(request, f"{count} refund(s) approved. Decision emails sent.")
    
    approve_refund.short_description = "Approve selected refund requests"
    
    def reject_refund(self, request, queryset):
        """Reject refund requests and send decision email"""
        count = 0
        for product in queryset:
            if product.refund_status == 'Requested':
                product.refund_status = 'Rejected'
                product.save()
                OrderTracking.objects.create(
                    order=product.order,
                    status='Refund Rejected',
                    description=f'Refund rejected for {product.product.product_name}.',
                    location=''
                )
                # Send rejection email to customer
                send_refund_decision_email(product, product.user, approved=False)
                count += 1
        self.message_user(request, f"{count} refund(s) rejected. Decision emails sent.")
    
    reject_refund.short_description = "Reject selected refund requests"
    
    def approve_cancellation(self, request, queryset):
        """Approve cancellation requests and send decision email"""
        count = 0
        for product in queryset:
            if product.cancellation_status == 'Cancellation Requested':
                product.cancellation_status = 'Cancelled'
                product.save()
                OrderTracking.objects.create(
                    order=product.order,
                    status='Cancellation Approved',
                    description=f'Cancellation approved for {product.product.product_name}.',
                    location=''
                )
                # Send approval email to customer
                send_cancellation_decision_email(product, product.user, approved=True)
                count += 1
        self.message_user(request, f"{count} cancellation(s) approved. Decision emails sent.")
    
    approve_cancellation.short_description = "Approve selected cancellation requests"

    def approve_return(self, request, queryset):
        """Approve return requests"""
        count = 0
        for product in queryset:
            if product.return_status == 'Requested':
                product.return_status = 'Approved'
                product.save()
                OrderTracking.objects.create(
                    order=product.order,
                    status='Return Approved',
                    description=f'Return approved for {product.product.product_name}.',
                    location=''
                )
                count += 1
        self.message_user(request, f"{count} return(s) approved.")

    approve_return.short_description = "Approve selected return requests"

    def reject_return(self, request, queryset):
        """Reject return requests"""
        count = 0
        for product in queryset:
            if product.return_status == 'Requested':
                product.return_status = 'Rejected'
                product.save()
                OrderTracking.objects.create(
                    order=product.order,
                    status='Return Rejected',
                    description=f'Return rejected for {product.product.product_name}.',
                    location=''
                )
                count += 1
        self.message_user(request, f"{count} return(s) rejected.")

    reject_return.short_description = "Reject selected return requests"
    
    actions = ['approve_refund', 'reject_refund', 'approve_cancellation', 'approve_return', 'reject_return']

admin.site.register(OrderProduct, OrderProductAdmin)

class OrderTrackingAdmin(admin.ModelAdmin):
    list_display = ('order', 'status', 'location', 'timestamp')
    search_fields = ('order__order_number', 'status', 'location')
    list_filter = ('status', 'timestamp')
    readonly_fields = ('timestamp',)
    
    def save_model(self, request, obj, form, change):
        """Override to sync order status when tracking is updated"""
        super().save_model(request, obj, form, change)
        
        # Sync order status based on latest tracking
        status_mapping = {
            'Order Confirmed': 'New',
            'Processing': 'Accepted',
            'Shipped': 'Accepted',
            'Out for Delivery': 'Accepted',
            'Delivered': 'Completed',
            'Cancelled': 'Cancelled',
            'Returned': 'Completed',
        }
        
        new_order_status = status_mapping.get(obj.status)
        if new_order_status:
            order = obj.order
            order.status = new_order_status
            order.save()

admin.site.register(OrderTracking, OrderTrackingAdmin)
