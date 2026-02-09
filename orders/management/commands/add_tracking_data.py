from django.core.management.base import BaseCommand
from orders.models import Order, OrderTracking
from datetime import datetime, timedelta

class Command(BaseCommand):
    help = 'Add sample tracking data to all orders'

    def handle(self, *args, **options):
        orders = Order.objects.filter(is_ordered=True)
        
        if not orders.exists():
            self.stdout.write(self.style.WARNING('No orders found in database'))
            return

        for order in orders:
            # Check if tracking already exists
            if order.tracking_history.exists():
                self.stdout.write(self.style.WARNING(f'Order {order.order_number} already has tracking data'))
                continue
            
            # Create tracking timeline
            base_time = order.created_at
            
            tracking_data = [
                {
                    'status': 'Order Confirmed',
                    'description': 'Your order has been confirmed and is being prepared',
                    'location': 'Warehouse, New York, NY',
                    'offset': 0
                },
                {
                    'status': 'Processing',
                    'description': 'Your order is being processed and packed',
                    'location': 'Fulfillment Center, New York, NY',
                    'offset': 1
                },
                {
                    'status': 'Shipped',
                    'description': 'Your order has been shipped',
                    'location': 'Distribution Center, New Jersey, NJ',
                    'offset': 2
                },
                {
                    'status': 'Out for Delivery',
                    'description': 'Your order is out for delivery today',
                    'location': 'Local Delivery Hub',
                    'offset': 3
                },
                {
                    'status': 'Delivered',
                    'description': 'Your order has been delivered',
                    'location': f'{order.city}, {order.state}',
                    'offset': 4
                }
            ]
            
            for data in tracking_data:
                timestamp = base_time + timedelta(days=data['offset'])
                OrderTracking.objects.create(
                    order=order,
                    status=data['status'],
                    description=data['description'],
                    location=data['location'],
                    timestamp=timestamp
                )
            
            self.stdout.write(self.style.SUCCESS(f'Added tracking data for order {order.order_number}'))
        
        self.stdout.write(self.style.SUCCESS('Successfully added tracking data to all orders'))
