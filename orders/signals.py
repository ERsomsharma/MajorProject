from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Order, OrderTracking

@receiver(post_save, sender=Order)
def create_or_update_tracking(sender, instance, created, **kwargs):
    """
    Automatically create/update tracking when order is created or status changes
    """
    
    if created:
        # Create initial tracking when order is first created (is_ordered=False)
        if not instance.is_ordered:
            # Order just created, will add tracking when payment is done
            pass
    
    # Check if this is the payment completion (is_ordered changed to True)
    if instance.is_ordered:
        # Check if order already has "Order Confirmed" tracking
        has_confirmed = instance.tracking_history.filter(status='Order Confirmed').exists()
        
        if not has_confirmed:
            # Create initial "Order Confirmed" tracking
            OrderTracking.objects.create(
                order=instance,
                status='Order Confirmed',
                description='Payment received. Your order has been confirmed and is being prepared.',
                location='Warehouse'
            )


@receiver(post_save, sender=OrderTracking)
def sync_order_status_with_tracking(sender, instance, created, **kwargs):
    """
    Sync Order status based on latest tracking status
    """
    if created:
        order = instance.order
        status_mapping = {
            'Order Confirmed': 'New',
            'Processing': 'Accepted',
            'Shipped': 'Accepted',
            'Out for Delivery': 'Accepted',
            'Delivered': 'Completed',
            'Cancelled': 'Cancelled',
            'Returned': 'Completed',
        }
        
        new_order_status = status_mapping.get(instance.status, order.status)
        
        if order.status != new_order_status:
            # Temporarily disconnect signal to avoid recursion
            post_save.disconnect(create_or_update_tracking, sender=Order)
            
            order.status = new_order_status
            order.save()
            
            # Reconnect signal
            post_save.connect(create_or_update_tracking, sender=Order)
