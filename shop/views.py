from rest_framework import viewsets, permissions, generics
from rest_framework.views import APIView
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from rest_framework.generics import RetrieveUpdateAPIView
from .forms import SignUpForm, ProfileForm, LoginForm
from django.views.generic import TemplateView
import json
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render, redirect, get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .serializers import LogoutSerializers
from django.contrib.auth import logout
from rest_framework.views import APIView
from rest_framework import status
from django.contrib.auth.hashers import check_password
from .models import CustomUser, Profile, Description
from .serializers import UserSerializer, ProfileSerializer, LoginSerializer, DescriptionSerializer



def register(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            profile, created = Profile.objects.get_or_create(user=user)
            if created:
                profile.some_field = 'default_value'
                profile.save()
            return redirect('home')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = SignUpForm()
    return render(request, 'udemy1/register.html', {'form': form})






def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            
            user = CustomUser.objects.filter(email=email).first()
            if user is None:
                # Проверяем похожие email
                similar_users = CustomUser.objects.filter(email__icontains=email[:5])
                similar_emails = [u.email for u in similar_users]
                return JsonResponse({'success': False, 'error': 'Пользователь не найден', 'suggestions': similar_emails}, status=400)
            
            if check_password(password, user.password):
                login(request, user)
                request.session['user_title'] = user.title
                return JsonResponse({'success': True, 'message': f'Вы вошли как {user.title}', 'redirect_url': '/'})
            else:
                return JsonResponse({'success': False, 'error': 'Неверный пароль'}, status=400)
        else:
            return JsonResponse({'success': False, 'error': 'Неверный ввод данных'}, status=400)
    
    else:
        form = LoginForm()
    return render(request, 'udemy1/login.html', {'form': form})



class HomeView(TemplateView):
    template_name = 'udemy1/home.html'


@csrf_exempt
def profile_view(request):
    profile = Profile.objects.get(user=request.user)

    if request.headers.get('Content-Type') == 'application/json':
        if request.method == 'GET':
            return JsonResponse({
                'username': request.user.username,
                'email': profile.email,
                'first_name': profile.first_name,
                'last_name': profile.last_name,
                'bio': profile.bio,
            })
        elif request.method == 'POST':
            try:
                data = json.loads(request.body)
                profile.first_name = data.get('first_name', profile.first_name)
                profile.last_name = data.get('last_name', profile.last_name)
                profile.bio = data.get('bio', profile.bio)
                profile.save()
                return JsonResponse({'status': 'success', 'message': 'Profile updated successfully!'})
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            return redirect('home')
    else:
        form = ProfileForm(instance=profile)

    return render(request, 'udemy1/profile.html', {'form': form, 'profile': profile})


def update_profile(request):
    profile, created = Profile.objects.get_or_create(user=request.user)
    if request.method == "POST":
        if any(field in request.POST for field in ['headline', 'description', 'email', 'first_name', 'last_name']):
            profile.headline = request.POST.get('headline', profile.headline)
            profile.description = request.POST.get('description', profile.description)
            profile.user.email = request.POST.get('email', profile.user.email)
            profile.user.first_name = request.POST.get('first_name', profile.user.first_name)
            profile.user.last_name = request.POST.get('last_name', profile.user.last_name)
            profile.user.save()
            profile.save()
            return redirect('home')
    return render(request, 'udemy1/update_profile.html', {'profile': profile})


@login_required
def change_name(request):
    if request.method == 'POST':
        new_name = request.POST.get('new_name')
        if new_name:
            request.user.last_name = new_name
            request.user.save()
        return redirect('update_profile')
    return render(request, 'udemy1/change_name.html')


@login_required
def change_password(request):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        if new_password == confirm_password:
            request.user.set_password(new_password)
            request.user.save()
            update_session_auth_hash(request, request.user)
            messages.success(request, "Your password has been changed successfully.")
            return redirect('update_profile')
        else:
            messages.error(request, "Passwords do not match. Please try again.")
    return render(request, 'udemy1/change_password.html')


@login_required
def change_email(request):
    if request.method == 'POST':
        new_email = request.POST.get('new_email')
        if new_email and new_email != request.user.email:
            request.user.email = new_email
            request.user.save()
            messages.success(request, 'Your email has been updated!')
            return redirect('home')
        else:
            messages.error(request, 'Invalid email or email is the same as the current one.')
    return render(request, 'udemy1/change_email.html')


@login_required
def change_headline(request):
    if request.method == "POST":
        profile = request.user.profile
        profile.headline = request.POST.get('headline')
        profile.save()
        return redirect('update_profile')
    return render(request, 'change_headline.html')

class RegisterView(APIView):
    def post(self, request, *args, **kwargs):
        form = SignUpForm(request.data)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginVicew(APIView):
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            login(request, user)
            return Response({"message": "User logged in successfully"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfileView(RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return Profile.objects.get(user=self.request.user)


class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        data = request.data
        new_email = data.get("email")
        if new_email and new_email != user.email:
            user.email = new_email
        new_username = data.get("username")
        if new_username and new_username != user.username:
            user.username = new_username
        new_password = data.get("password")
        confirm_password = data.get("confirm_password")
        if new_password and new_password == confirm_password:
            user.set_password(new_password)
            update_session_auth_hash(request, user)
        elif new_password and new_password != confirm_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
        user.save()
        return Response({"message": "Profile updated successfully"}, status=status.HTTP_200_OK)


class UserDataView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data)


class UpdateDescriptionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        description = Description.objects.first()
        serializer = DescriptionSerializer(description)
        return Response(serializer.data)

    def post(self, request):
        description = Description.objects.first()
        new_text = request.data.get("description")
        if new_text:
            description.text = new_text
            description.save()
            return Response({"message": "Description updated successfully"})
        return Response({"error": "Description not updated"}, status=status.HTTP_400_BAD_REQUEST)
    
def logout_view(request):
    logout(request)
    return redirect('home')

class LogoutView(APIView):
    def post(self, request):
        if request.user.is_authenticated:
            logout(request)
            return Response({"message": "Вы успешно вышли из системы."}, status=status.HTTP_200_OK)
        return Response({"error": "Пользователь не был авторизован."}, status=status.HTTP_400_BAD_REQUEST)