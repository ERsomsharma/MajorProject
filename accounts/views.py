from django.contrib import messages, auth
from django.shortcuts import redirect, render
from .forms import RegistrationForm
from .models import Account, MyAccountManager
from django.contrib.auth.decorators import login_required

# Additional imports for email verification
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags


# Create your views here.

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split('@')[0]
            
            user = Account.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email,
                username=username,
                password=password,
            )
            user.phone_number = phone_number
            user.save()

            #user activation can be added here
            current_site = get_current_site(request)
            mail_subject = 'Please activate your account'
            html_message = render_to_string('accounts/account_verification_email.html', {
                'user' : user,
                'domain' : current_site.domain,
                'uid' : urlsafe_base64_encode(force_bytes(user.pk)),
                'token' : default_token_generator.make_token(user),
                'protocol' : 'https' if request.is_secure() else 'http',
            })
            text_message = strip_tags(html_message)
            email_message = EmailMultiAlternatives(subject=mail_subject, body=text_message,from_email='no-reply@yourdomain.com  ' , to=[email])
            email_message.attach_alternative(html_message, "text/html")
            email_message.send()
            # messages.success(request, 'Thank you for registering. Please check your email to verify your account.')
            return redirect('/accounts/login/?command=verification&email='+email)
    else:
        form = RegistrationForm()

    context = {
        'form': form,
    }
    return render(request, 'accounts/register.html', context)

def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            messages.success(request, 'You are now logged in.')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid login credentials.')
            return redirect('login')
        
        
    return render(request, 'accounts/login.html')

@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('login')

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Thank you for your email confirmation. You can now login to your account.')
        return redirect('login')
    else:
        messages.error(request, 'Activation link is invalid!')
        return redirect('register')
    
@login_required(login_url='login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')

def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)

            # Password reset email logic can be added here
            current_site = get_current_site(request)
            mail_subject = 'Reset Your Password'
            html_message = render_to_string('accounts/reset_password_email.html', {
                'user' : user,
                'domain' : current_site.domain,
                'uid' : urlsafe_base64_encode(force_bytes(user.pk)),
                'token' : default_token_generator.make_token(user),
                'protocol' : 'https' if request.is_secure() else 'http',
            })
            text_message = strip_tags(html_message)
            email_message = EmailMultiAlternatives(subject=mail_subject, body=text_message,from_email='no-reply@yourdomain.com', to=[email])
            email_message.attach_alternative(html_message, "text/html")
            email_message.send()

            messages.success(request, 'Password reset instructions have been sent to your email.')
            return redirect('login')
        else:
            messages.error(request, 'Account does not exist with this email.')
            return redirect('forgotPassword')
    return render(request, 'accounts/forgotPassword.html')

def reset_password_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Please reset your password.')
        return redirect('resetPassword')
    else:
        messages.error(request, 'The reset password link is invalid!')
        return redirect('login')
    
def resetPassword(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password reset successful. You can now log in with your new password.')
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match.')
            return redirect('resetPassword')
    else:
        return render(request, 'accounts/resetPassword.html')


