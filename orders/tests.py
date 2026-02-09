from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.mail import outbox
from .models import Order, OrderProduct, OrderTracking, Payment
from store.models import Product, Category
import json

User = get_user_model()


class OrderModelTestCase(TestCase):
    """Test Order model functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.order = Order.objects.create(
            user=self.user,
            order_number='ORD-001',
            first_name='John',
            last_name='Doe',
            phone='1234567890',
            email='john@example.com',
            address_line_1='123 Main St',
            country='USA',
            state='CA',
            city='Los Angeles',
            pincode='90001',
            order_total=100.0,
            tax=10.0,
            status='New',
            is_ordered=True
        )
    
    def test_order_creation(self):
        """Test that order is created correctly"""
        self.assertEqual(self.order.order_number, 'ORD-001')
        self.assertEqual(self.order.first_name, 'John')
        self.assertEqual(self.order.status, 'New')
        self.assertTrue(self.order.is_ordered)
    
    def test_full_name_method(self):
        """Test full_name method"""
        self.assertEqual(self.order.full_name(), 'John Doe')
    
    def test_order_string_representation(self):
        """Test __str__ method"""
        self.assertEqual(str(self.order), 'John')


class OrderProductTestCase(TestCase):
    """Test OrderProduct model and refund/cancellation logic"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.category = Category.objects.create(
            category_name='Test Category',
            slug='test-category'
        )
        
        self.product = Product.objects.create(
            product_name='Test Product',
            slug='test-product',
            category=self.category,
            price=50.0,
            stock=10
        )
        
        self.order = Order.objects.create(
            user=self.user,
            order_number='ORD-001',
            first_name='John',
            last_name='Doe',
            phone='1234567890',
            email='john@example.com',
            address_line_1='123 Main St',
            country='USA',
            state='CA',
            city='Los Angeles',
            pincode='90001',
            order_total=100.0,
            tax=10.0,
            status='New',
            is_ordered=True
        )
        
        self.order_product = OrderProduct.objects.create(
            order=self.order,
            user=self.user,
            product=self.product,
            quantity=2,
            product_price=50.0,
            ordered=True
        )
    
    def test_order_product_creation(self):
        """Test OrderProduct creation"""
        self.assertEqual(self.order_product.product.product_name, 'Test Product')
        self.assertEqual(self.order_product.quantity, 2)
        self.assertEqual(self.order_product.refund_status, 'No Request')
        self.assertEqual(self.order_product.cancellation_status, 'Active')
    
    def test_refund_status_choices(self):
        """Test refund status choices"""
        self.order_product.refund_status = 'Requested'
        self.order_product.save()
        self.order_product.refresh_from_db()
        self.assertEqual(self.order_product.refund_status, 'Requested')
    
    def test_cancellation_status_choices(self):
        """Test cancellation status choices"""
        self.order_product.cancellation_status = 'Cancellation Requested'
        self.order_product.save()
        self.order_product.refresh_from_db()
        self.assertEqual(self.order_product.cancellation_status, 'Cancellation Requested')


class OrderTrackingTestCase(TestCase):
    """Test OrderTracking model"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.order = Order.objects.create(
            user=self.user,
            order_number='ORD-001',
            first_name='John',
            last_name='Doe',
            phone='1234567890',
            email='john@example.com',
            address_line_1='123 Main St',
            country='USA',
            state='CA',
            city='Los Angeles',
            pincode='90001',
            order_total=100.0,
            tax=10.0,
            status='New',
            is_ordered=True
        )
        
        self.tracking = OrderTracking.objects.create(
            order=self.order,
            status='Order Confirmed',
            description='Order confirmed',
            location='Warehouse'
        )
    
    def test_tracking_creation(self):
        """Test tracking entry creation"""
        self.assertEqual(self.tracking.status, 'Order Confirmed')
        self.assertEqual(self.tracking.location, 'Warehouse')
        self.assertIsNotNone(self.tracking.timestamp)


class RefundRequestTestCase(TestCase):
    """Test refund request functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.category = Category.objects.create(
            category_name='Test Category',
            slug='test-category'
        )
        
        self.product = Product.objects.create(
            product_name='Test Product',
            slug='test-product',
            category=self.category,
            price=50.0,
            stock=10
        )
        
        self.order = Order.objects.create(
            user=self.user,
            order_number='ORD-001',
            first_name='John',
            last_name='Doe',
            phone='1234567890',
            email='john@example.com',
            address_line_1='123 Main St',
            country='USA',
            state='CA',
            city='Los Angeles',
            pincode='90001',
            order_total=100.0,
            tax=10.0,
            status='Completed',
            is_ordered=True
        )
        
        self.order_product = OrderProduct.objects.create(
            order=self.order,
            user=self.user,
            product=self.product,
            quantity=2,
            product_price=50.0,
            ordered=True
        )
        
        OrderTracking.objects.create(
            order=self.order,
            status='Delivered'
        )
    
    def test_refund_request_requires_login(self):
        """Test that refund request requires authentication"""
        response = self.client.post(
            reverse('request_refund'),
            data=json.dumps({'order_product_id': self.order_product.id, 'reason': 'Test'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_refund_request_post_method_only(self):
        """Test that GET requests are not allowed"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('request_refund'))
        self.assertEqual(response.status_code, 405)  # Method not allowed
    
    def test_refund_request_successful(self):
        """Test successful refund request"""
        self.client.login(username='testuser', password='testpass123')
        
        response = self.client.post(
            reverse('request_refund'),
            data=json.dumps({
                'order_product_id': self.order_product.id,
                'reason': 'Product not as described'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        
        # Verify status changed in database
        self.order_product.refresh_from_db()
        self.assertEqual(self.order_product.refund_status, 'Requested')
    
    def test_refund_request_already_requested(self):
        """Test that refund can't be requested twice"""
        self.order_product.refund_status = 'Requested'
        self.order_product.save()
        
        self.client.login(username='testuser', password='testpass123')
        
        response = self.client.post(
            reverse('request_refund'),
            data=json.dumps({
                'order_product_id': self.order_product.id,
                'reason': 'Test'
            }),
            content_type='application/json'
        )
        
        data = json.loads(response.content)
        self.assertFalse(data['success'])
        self.assertIn('already requested', data['message'].lower())
    
    def test_refund_email_sent(self):
        """Test that email is sent on refund request"""
        self.client.login(username='testuser', password='testpass123')
        
        with self.settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend'):
            response = self.client.post(
                reverse('request_refund'),
                data=json.dumps({
                    'order_product_id': self.order_product.id,
                    'reason': 'Test'
                }),
                content_type='application/json'
            )
            
            # Check that emails were sent (customer + admin)
            self.assertGreaterEqual(len(outbox), 1)


class CancellationRequestTestCase(TestCase):
    """Test cancellation request functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.category = Category.objects.create(
            category_name='Test Category',
            slug='test-category'
        )
        
        self.product = Product.objects.create(
            product_name='Test Product',
            slug='test-product',
            category=self.category,
            price=50.0,
            stock=10
        )
        
        self.order = Order.objects.create(
            user=self.user,
            order_number='ORD-001',
            first_name='John',
            last_name='Doe',
            phone='1234567890',
            email='john@example.com',
            address_line_1='123 Main St',
            country='USA',
            state='CA',
            city='Los Angeles',
            pincode='90001',
            order_total=100.0,
            tax=10.0,
            status='New',
            is_ordered=True
        )
        
        self.order_product = OrderProduct.objects.create(
            order=self.order,
            user=self.user,
            product=self.product,
            quantity=2,
            product_price=50.0,
            ordered=True
        )
    
    def test_cancellation_request_requires_login(self):
        """Test that cancellation request requires authentication"""
        response = self.client.post(
            reverse('request_cancellation'),
            data=json.dumps({'order_product_id': self.order_product.id, 'reason': 'Test'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_cancellation_request_successful(self):
        """Test successful cancellation request"""
        self.client.login(username='testuser', password='testpass123')
        
        response = self.client.post(
            reverse('request_cancellation'),
            data=json.dumps({
                'order_product_id': self.order_product.id,
                'reason': 'Changed my mind'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        
        # Verify status changed in database
        self.order_product.refresh_from_db()
        self.assertEqual(self.order_product.cancellation_status, 'Cancellation Requested')
    
    def test_cancellation_not_available_when_cancelled(self):
        """Test that cancellation can't be requested again"""
        self.order_product.cancellation_status = 'Cancelled'
        self.order_product.save()
        
        self.client.login(username='testuser', password='testpass123')
        
        response = self.client.post(
            reverse('request_cancellation'),
            data=json.dumps({
                'order_product_id': self.order_product.id,
                'reason': 'Test'
            }),
            content_type='application/json'
        )
        
        data = json.loads(response.content)
        self.assertFalse(data['success'])


class OrderTrackingViewTestCase(TestCase):
    """Test order tracking view functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.order = Order.objects.create(
            user=self.user,
            order_number='ORD-001',
            first_name='John',
            last_name='Doe',
            phone='1234567890',
            email='john@example.com',
            address_line_1='123 Main St',
            country='USA',
            state='CA',
            city='Los Angeles',
            pincode='90001',
            order_total=100.0,
            tax=10.0,
            status='New',
            is_ordered=True
        )
        
        OrderTracking.objects.create(
            order=self.order,
            status='Order Confirmed'
        )
    
    def test_order_tracking_view_requires_login(self):
        """Test that tracking page requires authentication"""
        response = self.client.get(
            reverse('order_tracking', args=['ORD-001'])
        )
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_order_tracking_view_loads(self):
        """Test that tracking page loads for authenticated user"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(
            reverse('order_tracking', args=['ORD-001'])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Order Tracking')
    
    def test_order_tracking_not_found(self):
        """Test tracking page with non-existent order"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(
            reverse('order_tracking', args=['ORD-999'])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Order not found')


class AuthorizationTestCase(TestCase):
    """Test authorization and access control"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='testpass123'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='testpass123'
        )
        
        self.category = Category.objects.create(
            category_name='Test Category',
            slug='test-category'
        )
        
        self.product = Product.objects.create(
            product_name='Test Product',
            slug='test-product',
            category=self.category,
            price=50.0,
            stock=10
        )
        
        self.order = Order.objects.create(
            user=self.user1,
            order_number='ORD-001',
            first_name='John',
            last_name='Doe',
            phone='1234567890',
            email='john@example.com',
            address_line_1='123 Main St',
            country='USA',
            state='CA',
            city='Los Angeles',
            pincode='90001',
            order_total=100.0,
            tax=10.0,
            status='Completed',
            is_ordered=True
        )
        
        self.order_product = OrderProduct.objects.create(
            order=self.order,
            user=self.user1,
            product=self.product,
            quantity=1,
            product_price=50.0,
            ordered=True
        )
        
        OrderTracking.objects.create(
            order=self.order,
            status='Delivered'
        )
    
    def test_user_cannot_access_other_user_orders(self):
        """Test that users can't request refund for other user's orders"""
        self.client.login(username='user2', password='testpass123')
        
        response = self.client.post(
            reverse('request_refund'),
            data=json.dumps({
                'order_product_id': self.order_product.id,
                'reason': 'Test'
            }),
            content_type='application/json'
        )
        
        data = json.loads(response.content)
        self.assertFalse(data['success'])
        self.assertIn('not found', data['message'].lower())

