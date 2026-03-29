from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, CompteBancaire, SecurityEvent, Alert

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ['username', 'email', 'role', 'is_staff', 'is_locked']
    fieldsets = UserAdmin.fieldsets + (
        ('Informations SIEM', {'fields': ('role', 'is_locked')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Informations SIEM', {'fields': ('role', 'is_locked')}),
    )

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(CompteBancaire)
admin.site.register(SecurityEvent)
admin.site.register(Alert)