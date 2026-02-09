from django.db import models
from accounts.models import Account
from store.models import Product, Variation

# Create your models here.

class Payment(models.Model):
    user = models.ForeignKey(Account, on_delete=models.CASCADE)
    payment_id = models.CharField(max_length=100)
    payment_method = models.CharField(max_length=100)
    amount_paid = models.CharField(max_length=100) # this is the total amount paid
    status = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.payment_id
    
class Order(models.Model):
    STATUS = (
        ('New' , 'New'),
        ('Accepted' , 'Accepted'),
        ('Completed' , 'Completed'),
        ('Cancelled' , 'Cancelled'),
    )
    user = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True)
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, blank=True, null=True)
    order_number = models.CharField(max_length=20)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    phone = models.CharField(max_length=15)
    email = models.EmailField(max_length=50)
    address_line_1 = models.CharField(max_length=50)
    address_line_2 = models.CharField(max_length=50, blank=True)
    country = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    pincode = models.CharField(max_length=10, blank=True)
    order_note = models.CharField(max_length=100, blank=True)
    order_total = models.FloatField()
    tax = models.FloatField()
    status = models.CharField(max_length=10, choices=STATUS, default='New')
    ip = models.CharField(max_length=20, blank=True)
    is_ordered = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def full_name(self):
        return f'{self.first_name} {self.last_name}'
    
    def full_address(self):
        return f'{self.address_line_1} {self.address_line_2}'

    def __str__(self):
        return self.first_name
    
class OrderProduct(models.Model):
    REFUND_STATUS = (
        ('No Request', 'No Request'),
        ('Requested', 'Requested'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
    )

    RETURN_STATUS = (
        ('No Request', 'No Request'),
        ('Requested', 'Requested'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
    )
    
    CANCELLATION_STATUS = (
        ('Active', 'Active'),
        ('Cancellation Requested', 'Cancellation Requested'),
        ('Cancelled', 'Cancelled'),
    )
    
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, blank=True, null=True)
    user = models.ForeignKey(Account, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    variations = models.ManyToManyField(Variation, blank=True)
    quantity = models.IntegerField()
    product_price = models.FloatField()
    ordered = models.BooleanField(default=False)
    refund_status = models.CharField(max_length=15, choices=REFUND_STATUS, default='No Request')
    cancellation_status = models.CharField(max_length=25, choices=CANCELLATION_STATUS, default='Active')
    return_status = models.CharField(max_length=15, choices=RETURN_STATUS, default='No Request')
    refund_reason = models.TextField(blank=True, null=True)
    cancellation_reason = models.TextField(blank=True, null=True)
    return_reason = models.TextField(blank=True, null=True)
    refund_requested_at = models.DateTimeField(blank=True, null=True)
    cancellation_requested_at = models.DateTimeField(blank=True, null=True)
    return_requested_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.product.product_name


class OrderTracking(models.Model):
    TRACKING_STATUS = (
        ('Order Confirmed', 'Order Confirmed'),
        ('Processing', 'Processing'),
        ('Shipped', 'Shipped'),
        ('Out for Delivery', 'Out for Delivery'),
        ('Delivered', 'Delivered'),
        ('Refund Requested', 'Refund Requested'),
        ('Refund Approved', 'Refund Approved'),
        ('Refund Rejected', 'Refund Rejected'),
        ('Cancellation Requested', 'Cancellation Requested'),
        ('Cancellation Approved', 'Cancellation Approved'),
        ('Cancellation Rejected', 'Cancellation Rejected'),
        ('Return Requested', 'Return Requested'),
        ('Return Approved', 'Return Approved'),
        ('Return Rejected', 'Return Rejected'),
        ('Cancelled', 'Cancelled'),
        ('Returned', 'Returned'),
    )
    
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='tracking_history')
    status = models.CharField(max_length=30, choices=TRACKING_STATUS)
    description = models.CharField(max_length=200, blank=True)
    location = models.CharField(max_length=100, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f'{self.order.order_number} - {self.status}'

