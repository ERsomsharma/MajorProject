from django.shortcuts import redirect, render
from .models import Order, OrderTracking, OrderProduct
from carts.models import CartItem
from .forms import OrderForm
import datetime
from django.http import HttpResponse, JsonResponse
from .models import Order, Payment, OrderProduct
import json
from store.models import Product
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.conf import settings
import os
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from accounts.models import UserProfile

# Create your views here.

def payments(request):
    body = json.loads(request.body)
    order = Order.objects.get(user=request.user, is_ordered=False, order_number=body['orderID'])
    # store the transaction details inside Payment model

    payment = Payment(
        user = request.user,
        payment_id = body['transID'],
        payment_method = body['payment_method'],
        amount_paid = order.order_total,
        status = body['status'],
    )
    payment.save()

    order.payment = payment
    order.is_ordered = True
    order.status = 'New'  # Set initial status to New when payment is done
    order.save()
    
    # Signal will automatically create "Order Confirmed" tracking entry

    # Move the cart items to Order Product table
    cart_items = CartItem.objects.filter(user=request.user)
    for item in cart_items:
        orderproduct = OrderProduct()
        orderproduct.order_id = order.id
        orderproduct.payment = payment
        orderproduct.user_id = request.user.id
        orderproduct.product_id = item.product_id
        orderproduct.quantity = item.quantity
        orderproduct.product_price = item.product.price
        orderproduct.ordered = True
        orderproduct.save()

        cart_item = CartItem.objects.get(id=item.id)
        product_variation = cart_item.variations.all()
        orderproduct = OrderProduct.objects.get(id=orderproduct.id)
        orderproduct.variations.set(product_variation)
        orderproduct.save()

    # Reduce the quantity of the sold products
        product = Product.objects.get(id=item.product_id)
        product.stock -= item.quantity
        product.save()

    # Clear cart
    CartItem.objects.filter(user=request.user).delete()

    # Send order received email to customer
    mail_subject = 'Thank you for your order!'
    ordered_products = OrderProduct.objects.filter(order=order)
    for i in ordered_products:
        i.total = i.product_price * i.quantity
    message = render_to_string('orders/order_received_email.html', {
        'user': request.user,
        'order': order,
        'ordered_products': ordered_products,
        'protocol': 'http' if request.is_secure() else 'https',
        'domain': request.get_host(),
    })
    to_email = request.user.email
    email = EmailMultiAlternatives(mail_subject, strip_tags(message), to=[to_email])
    email.attach_alternative(message, "text/html")
    # Attach logo
    logo_path = os.path.join(settings.STATIC_ROOT, 'images', 'logo.png')
    if os.path.exists(logo_path):
        with open(logo_path, 'rb') as f:
            email.attach('logo.png', f.read(), 'image/png')
    # Attach payments image
    payments_path = os.path.join(settings.STATIC_ROOT, 'images', 'misc', 'payments.png')
    if os.path.exists(payments_path):
        with open(payments_path, 'rb') as f:
            email.attach('payments.png', f.read(), 'image/png')
    email.send()

    # Send order number and transaction id back to sendData method via JsonResponse
    data = {
        'order_number': order.order_number,
        'transID': payment.payment_id,
        'status': payment.status,
        'amount_paid': payment.amount_paid,
        'payment_method': payment.payment_method,
    }
    return JsonResponse(data)


    return render(request, "orders/payments.html")


def place_order(request, total=0, quantity=0,):
    current_user = request.user

    # if the cart count is less than or equal to 0, then redirect back to shopping
    cart_items = CartItem.objects.filter(user=current_user)
    cart_count = cart_items.count()
    if cart_count <= 0:
        return redirect('store')
    
    grand_total = 0
    tax = 0

    for cart_item in cart_items:
        total += (cart_item.product.price * cart_item.quantity)
        quantity += cart_item.quantity
    tax = (2 * total) / 100
    grand_total = total + tax

    if request.method == 'POST':
        form = OrderForm(request.POST)
        if form.is_valid():
            # store all billing information inside Order table
            data = Order()
            data.user = current_user
            data.first_name = form.cleaned_data['first_name']
            data.last_name = form.cleaned_data['last_name']
            data.phone = form.cleaned_data['phone']
            data.email = form.cleaned_data['email']
            data.address_line_1 = form.cleaned_data['address_line_1']
            data.address_line_2 = form.cleaned_data['address_line_2']
            data.country = form.cleaned_data['country']
            data.state = form.cleaned_data['state']
            data.city = form.cleaned_data['city']
            data.pincode = form.cleaned_data['pincode']
            data.order_note = form.cleaned_data['order_note']
            data.order_total = grand_total  # This should be calculated based on cart items
            data.tax = tax           # This should be calculated based on cart items
            data.ip = request.META.get('REMOTE_ADDR')
            data.save()

            # Generate order number
            yr = int(datetime.date.today().strftime('%Y'))
            dt = int(datetime.date.today().strftime('%d'))
            mt = int(datetime.date.today().strftime('%m'))
            d = datetime.date(yr, mt, dt)
            current_date = d.strftime("%Y%m%d")  # YYYYMMDD
            order_number = current_date + str(data.id)
            data.order_number = order_number
            data.save()

            order = Order.objects.get(user=current_user, is_ordered=False, order_number=order_number)
            context = {
                'order': order,
                'cart_items': cart_items,
                'total': total,
                'tax': tax,
                'grand_total': grand_total,
            }
            return render(request, 'orders/payments.html', context)
    else:
        return redirect('checkout') 
    

def order_complete(request):
    order_number = request.GET.get('order_number')
    transID = request.GET.get('payment_id')
    try:
        order = Order.objects.get(order_number=order_number, is_ordered=True)
        ordered_products = OrderProduct.objects.filter(order_id=order.id)

        subtotal = 0
        for i in ordered_products:
            subtotal += i.product_price * i.quantity

        payment = Payment.objects.get(payment_id=transID)

        context = {
            'order': order,
            'ordered_products': ordered_products,
            'order_number': order.order_number,
            'transID': payment.payment_id,
            'payment': payment,
            'subtotal': subtotal,
        }
        return render(request, 'orders/order_complete.html', context)
    except (Payment.DoesNotExist, Order.DoesNotExist):
        pass
    return render(request, "orders/order_complete.html")

def order_detail(request, order_id):
    order = Order.objects.get(order_number=order_id)
    ordered_products = OrderProduct.objects.filter(order_id=order.id)

    subtotal = 0
    for i in ordered_products:
        i.total = i.product_price * i.quantity
        subtotal += i.total

    context = {
        'order': order,
        'ordered_products': ordered_products,
        'subtotal': subtotal,
    }
    return render(request, 'orders/order_detail.html', context)


def order_tracking(request, order_number):
    """Display order tracking information"""
    try:
        order = Order.objects.get(order_number=order_number, user=request.user)
        tracking_history = OrderTracking.objects.filter(order=order)
        
        # Get the latest tracking status
        latest_tracking = tracking_history.first() if tracking_history.exists() else None
        
        context = {
            'order': order,
            'tracking_history': tracking_history,
            'latest_tracking': latest_tracking,
        }
        return render(request, 'orders/order_tracking.html', context)
    except Order.DoesNotExist:
        return render(request, 'orders/order_tracking.html', {'error': 'Order not found'})


def order_list(request):
    """Display all orders for the logged-in user"""
    if request.user.is_authenticated:
        orders = Order.objects.filter(user=request.user, is_ordered=True).order_by('-created_at')
        context = {
            'orders': orders,
        }
        return render(request, 'orders/order_list.html', context)
    else:
        return redirect('login')


@login_required(login_url='login')
@require_http_methods(["POST"])
def request_refund(request):
    """Handle refund request for a product"""
    try:
        data = json.loads(request.body)
        order_product_id = data.get('order_product_id')
        reason = data.get('reason', '')
        
        order_product = OrderProduct.objects.get(id=order_product_id, user=request.user)
        
        # Check if product can be refunded (only if order is Completed or Delivered)
        order = order_product.order
        latest_tracking = order.tracking_history.first()
        
        can_refund = order.status == 'Completed' or (latest_tracking and latest_tracking.status == 'Delivered')

        if not can_refund:
            return JsonResponse({
                'success': False,
                'message': 'Refund is only available after delivery.'
            })

        if order_product.refund_status == 'No Request':
            order_product.refund_status = 'Requested'
            order_product.refund_reason = reason
            order_product.refund_requested_at = datetime.datetime.now()
            order_product.save()

            OrderTracking.objects.create(
                order=order,
                status='Refund Requested',
                description=f'Refund requested for {order_product.product.product_name}.',
                location=''
            )
            
            # Send refund request email to admin and customer
            send_refund_request_email(order_product, request.user)
            
            return JsonResponse({
                'success': True,
                'message': f'Refund request submitted for {order_product.product.product_name}. You will receive an email confirmation shortly.',
                'refund_status': order_product.refund_status,
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'You have already requested a refund for this product.'
            })
    except OrderProduct.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Product not found in your order.'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        })


@login_required(login_url='login')
@require_http_methods(["POST"])
def request_cancellation(request):
    """Handle product cancellation request"""
    try:
        data = json.loads(request.body)
        order_product_id = data.get('order_product_id')
        reason = data.get('reason', '')
        
        order_product = OrderProduct.objects.get(id=order_product_id, user=request.user)
        
        latest_tracking = order_product.order.tracking_history.first()
        is_in_transit = latest_tracking and latest_tracking.status in ['Shipped', 'Out for Delivery', 'Delivered']

        if is_in_transit:
            return JsonResponse({
                'success': False,
                'message': 'Cancellation is not available once the order is in transit.'
            })

        if order_product.cancellation_status == 'Active':
            order_product.cancellation_status = 'Cancellation Requested'
            order_product.cancellation_reason = reason
            order_product.cancellation_requested_at = datetime.datetime.now()
            order_product.save()

            OrderTracking.objects.create(
                order=order_product.order,
                status='Cancellation Requested',
                description=f'Cancellation requested for {order_product.product.product_name}.',
                location=''
            )
            
            # Send cancellation request email to admin and customer
            send_cancellation_request_email(order_product, request.user)
            
            return JsonResponse({
                'success': True,
                'message': f'Cancellation request submitted for {order_product.product.product_name}. Please wait for admin confirmation.',
                'cancellation_status': order_product.cancellation_status,
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'This product has already been cancelled or cancellation is not available.'
            })
    except OrderProduct.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Product not found in your order.'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        })


@login_required(login_url='login')
@require_http_methods(["POST"])
def request_return(request):
    """Handle return request for a delivered product"""
    try:
        data = json.loads(request.body)
        order_product_id = data.get('order_product_id')
        reason = data.get('reason', '')

        order_product = OrderProduct.objects.get(id=order_product_id, user=request.user)

        if order_product.refund_status != 'No Request':
            return JsonResponse({
                'success': False,
                'message': 'Return is not available while a refund is in progress.'
            })

        if order_product.cancellation_status != 'Active':
            return JsonResponse({
                'success': False,
                'message': 'Return is not available for cancelled products.'
            })

        order = order_product.order
        latest_tracking = order.tracking_history.first()
        can_return = order.status == 'Completed' or (latest_tracking and latest_tracking.status == 'Delivered')

        if not can_return:
            return JsonResponse({
                'success': False,
                'message': 'Return is only available after delivery.'
            })

        if order_product.return_status == 'No Request':
            order_product.return_status = 'Requested'
            order_product.return_reason = reason
            order_product.return_requested_at = datetime.datetime.now()
            order_product.save()

            OrderTracking.objects.create(
                order=order,
                status='Return Requested',
                description=f'Return requested for {order_product.product.product_name}.',
                location=''
            )

            return JsonResponse({
                'success': True,
                'message': f'Return request submitted for {order_product.product.product_name}.',
                'return_status': order_product.return_status,
            })

        return JsonResponse({
            'success': False,
            'message': 'You have already requested a return for this product.'
        })
    except OrderProduct.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Product not found in your order.'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        })


def send_refund_request_email(order_product, user):
    """Send refund request email to customer"""
    mail_subject = f'Refund Request Submitted - {order_product.product.product_name}'
    
    context = {
        'user': user,
        'order': order_product.order,
        'order_product': order_product,
        'reason': order_product.refund_reason,
        'amount': order_product.product_price * order_product.quantity,
    }
    
    message = render_to_string('orders/refund_request_email.html', context)
    to_email = user.email
    
    email = EmailMultiAlternatives(mail_subject, strip_tags(message), to=[to_email])
    email.attach_alternative(message, "text/html")
    
    # Also send to admin
    admin_message = render_to_string('orders/refund_request_admin_email.html', context)
    admin_email = EmailMultiAlternatives(
        f'[ADMIN] Refund Request - {order_product.product.product_name}',
        strip_tags(admin_message),
        to=[settings.DEFAULT_FROM_EMAIL]
    )
    admin_email.attach_alternative(admin_message, "text/html")
    
    email.send()
    admin_email.send()


def send_cancellation_request_email(order_product, user):
    """Send cancellation request email to customer"""
    mail_subject = f'Cancellation Request Submitted - {order_product.product.product_name}'
    
    context = {
        'user': user,
        'order': order_product.order,
        'order_product': order_product,
        'reason': order_product.cancellation_reason,
        'amount': order_product.product_price * order_product.quantity,
    }
    
    message = render_to_string('orders/cancellation_request_email.html', context)
    to_email = user.email
    
    email = EmailMultiAlternatives(mail_subject, strip_tags(message), to=[to_email])
    email.attach_alternative(message, "text/html")
    
    # Also send to admin
    admin_message = render_to_string('orders/cancellation_request_admin_email.html', context)
    admin_email = EmailMultiAlternatives(
        f'[ADMIN] Cancellation Request - {order_product.product.product_name}',
        strip_tags(admin_message),
        to=[settings.DEFAULT_FROM_EMAIL]
    )
    admin_email.attach_alternative(admin_message, "text/html")
    
    email.send()
    admin_email.send()


def send_refund_decision_email(order_product, user, approved=True):
    """Send refund decision email to customer when admin approves/rejects"""
    if approved:
        mail_subject = f'Refund Request APPROVED - {order_product.product.product_name}'
        template = 'orders/refund_approved_email.html'
    else:
        mail_subject = f'Refund Request REJECTED - {order_product.product.product_name}'
        template = 'orders/refund_rejected_email.html'
    
    context = {
        'user': user,
        'order': order_product.order,
        'order_product': order_product,
        'amount': order_product.product_price * order_product.quantity,
    }
    
    message = render_to_string(template, context)
    to_email = user.email
    
    email = EmailMultiAlternatives(mail_subject, strip_tags(message), to=[to_email])
    email.attach_alternative(message, "text/html")
    email.send()


def send_cancellation_decision_email(order_product, user, approved=True):
    """Send cancellation decision email to customer when admin approves/rejects"""
    if approved:
        mail_subject = f'Cancellation Request APPROVED - {order_product.product.product_name}'
        template = 'orders/cancellation_approved_email.html'
    else:
        mail_subject = f'Cancellation Request REJECTED - {order_product.product.product_name}'
        template = 'orders/cancellation_rejected_email.html'
    
    context = {
        'user': user,
        'order': order_product.order,
        'order_product': order_product,
        'amount': order_product.product_price * order_product.quantity,
    }
    
    message = render_to_string(template, context)
    to_email = user.email
    
    email = EmailMultiAlternatives(mail_subject, strip_tags(message), to=[to_email])
    email.attach_alternative(message, "text/html")
    email.send() 