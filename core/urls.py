from django.urls import path
from .views import (
    login_view, logout_view, data_view, register_view, 
    profile_view, users_manage_view, toggle_user_lock, 
    change_user_role, transfer_funds, update_balance, 
    create_account_view, history_view, user_create_view,
    user_edit_view, user_detail_view
)

urlpatterns = [
    path('', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    path('profile/', profile_view, name='profile'),
    path('data/', data_view, name='data'),
    path('history/', history_view, name='history'),
    path('users/manage/', users_manage_view, name='users_manage'),
    path('users/create/', user_create_view, name='user_create'),
    path('users/<int:user_id>/edit/', user_edit_view, name='user_edit'),
    path('users/<int:user_id>/', user_detail_view, name='user_detail'),
    path('users/toggle/<int:user_id>/', toggle_user_lock, name='toggle_user_lock'),
    path('users/role/<int:user_id>/', change_user_role, name='change_user_role'),
    path('transfer-funds/', transfer_funds, name='transfer_funds'),
    path('update-balance/<int:account_id>/', update_balance, name='update_balance'),
    path('account/create/', create_account_view, name='create_account'),
]