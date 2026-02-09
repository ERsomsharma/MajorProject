from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('orders', '0008_alter_ordertracking_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='orderproduct',
            name='return_status',
            field=models.CharField(choices=[('No Request', 'No Request'), ('Requested', 'Requested'), ('Approved', 'Approved'), ('Rejected', 'Rejected')], default='No Request', max_length=15),
        ),
        migrations.AddField(
            model_name='orderproduct',
            name='return_reason',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='orderproduct',
            name='return_requested_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='ordertracking',
            name='status',
            field=models.CharField(choices=[('Order Confirmed', 'Order Confirmed'), ('Processing', 'Processing'), ('Shipped', 'Shipped'), ('Out for Delivery', 'Out for Delivery'), ('Delivered', 'Delivered'), ('Refund Requested', 'Refund Requested'), ('Refund Approved', 'Refund Approved'), ('Refund Rejected', 'Refund Rejected'), ('Cancellation Requested', 'Cancellation Requested'), ('Cancellation Approved', 'Cancellation Approved'), ('Cancellation Rejected', 'Cancellation Rejected'), ('Return Requested', 'Return Requested'), ('Return Approved', 'Return Approved'), ('Return Rejected', 'Return Rejected'), ('Cancelled', 'Cancelled'), ('Returned', 'Returned')], max_length=30),
        ),
    ]
