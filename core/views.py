import re, random, string
from decimal import Decimal, InvalidOperation
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.core.cache import cache
from django.utils import timezone
from django.db import transaction
from .models import CompteBancaire, CustomUser, Transaction, SecurityEvent
from security.signals import (
    sql_injection_detected, mass_access_detected, off_hours_access, 
    transaction_threshold_exceeded, repeated_account_consultation, 
    unauthorized_modification, privilege_escalation
)
from security.models import SecurityRule
from django.contrib.auth.forms import UserCreationForm, UserChangeForm

def is_admin(user):
    return user.is_superuser or user.role == 'admin'

# Formulaire d'inscription personnalisé
class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ['username']

class UserAdminCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ('username', 'role', 'is_locked')

class UserAdminEditForm(UserChangeForm):
    password = None # On ne gère pas le mot de passe ici par simplicité
    class Meta:
        model = CustomUser
        fields = ('username', 'role', 'is_locked', 'is_active')

def register_view(request):
    if request.method == 'POST':
        if request.POST.get('email_verify'):
            SecurityEvent.objects.create(
                username='bot_candidate', 
                ip_address=request.META.get('REMOTE_ADDR'), 
                event_type='honeypot_triggered',
                severity='critical',
                description="Honeypot 'email_verify' rempli (Bot détecté)"
            )
            messages.error(request, "Accès refusé.")
            return redirect('login')

        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # On force le rôle "utilisateur" pour les nouveaux clients
            user = CustomUser.objects.get(username=user.username)
            user.role = 'utilisateur'
            user.save()
            
            messages.success(request, "Compte créé avec succès ! Vous pouvez maintenant vous connecter.")
            return redirect('login')
        else:
            messages.error(request, "Erreur lors de la création du compte.")
    else:
        form = CustomUserCreationForm()
    return render(request, 'core/register.html', {'form': form})

def login_view(request):
    next_url = request.POST.get('next') or request.GET.get('next')
    
    if request.user.is_authenticated:
        if next_url:
            return redirect(next_url)
        if request.user.role in ['admin', 'analyste'] or request.user.is_superuser:
            return redirect('security_dashboard')
        return redirect('data')
    
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user and not user.is_locked:
            login(request, user)
            messages.success(request, f"Bienvenue {user.username} !")
            if next_url:
                try:
                    return redirect(next_url)
                except:
                    pass
            if user.role in ['admin', 'analyste'] or user.is_superuser:
                return redirect('security_dashboard')
            return redirect('data')
        else:
            messages.error(request, "Identifiants invalides ou compte verrouillé")
    return render(request, 'core/login.html', {'next': next_url})

@login_required
def profile_view(request):
    """Affiche le profil utilisateur et son historique de sécurité personnel"""
    personal_events = SecurityEvent.objects.filter(username=request.user.username).order_by('-timestamp')[:50]
    return render(request, 'core/profile.html', {
        'events': personal_events
    })

@login_required
def data_view(request):
    """Affiche les comptes accessibles à l'utilisateur."""
    # Accès global pour Admins / Superusers
    if request.user.role == 'admin' or request.user.is_superuser:
        comptes = CompteBancaire.objects.all()
    else:
        # Les analystes et utilisateurs ne voient que LEURS propres comptes
        comptes = CompteBancaire.objects.filter(owner=request.user)

    # Règle 8 : Lecture répétée d'un même compte
    target_id = request.GET.get('target')
    if target_id:
        try:
            rule_r8 = SecurityRule.objects.get(code='repeated_reading')
            if rule_r8.is_active:
                limit = rule_r8.parameters.get('limit', 5)
                window = rule_r8.parameters.get('window', 180)

                cache_key = f"repeat_read_{request.user.id}_{target_id}"
                count = cache.get(cache_key, 0) + 1
                cache.set(cache_key, count, window)
                if count > limit:
                    repeated_account_consultation.send(
                        sender=None, username=request.user.username, 
                        ip=request.META.get('REMOTE_ADDR'), account_id=target_id
                    )
        except SecurityRule.DoesNotExist:
            pass

    return render(request, 'core/data.html', {'comptes': comptes})

@login_required
def transfer_funds(request):
    """Gère les virements entre comptes"""
    if request.method == 'POST':
        source_id = request.POST.get('source_id')
        target_id = request.POST.get('target_id')
        try:
            amount = Decimal(request.POST.get('amount', '0'))
        except (ValueError, TypeError, InvalidOperation):
            messages.error(request, "Montant invalide.")
            return redirect('data')

        if amount <= 0:
            messages.error(request, "Le montant doit être supérieur à 0.")
            return redirect('data')

        # Vérification du seuil de transaction SIEM
        try:
            rule = SecurityRule.objects.get(code='transaction_limit')
            if rule.is_active:
                threshold = Decimal(rule.parameters.get('threshold', 1000000))
                if amount > threshold:
                    transaction_threshold_exceeded.send(
                        sender=None, 
                        username=request.user.username,
                        amount=amount,
                        threshold=threshold,
                        ip=request.META.get('REMOTE_ADDR')
                    )
        except SecurityRule.DoesNotExist:
            pass

        with transaction.atomic():
            # Vérifier l'existence et l'appartenance du compte source
            source_acc = get_object_or_404(CompteBancaire, id_compte=source_id)
            if source_acc.owner != request.user and not request.user.is_superuser:
                messages.error(request, "Action non autorisée sur ce compte.")
                return redirect('data')

            if source_acc.solde < amount:
                messages.error(request, "Solde insuffisant.")
                return redirect('data')

            # Vérifier le compte cible
            target_acc = CompteBancaire.objects.filter(id_compte=target_id).first()
            if not target_acc:
                messages.error(request, "Compte destinataire introuvable.")
                return redirect('data')

            if source_acc == target_acc:
                messages.error(request, "Transaction vers le même compte impossible.")
                return redirect('data')

            # Effectuer le transfert
            source_acc.solde -= amount
            target_acc.solde += amount
            
            now = timezone.now().strftime("%d/%m/%Y %H:%M")
            source_acc.historique += f"\n[{now}] Virement envoyé: -{amount} FCFA vers {target_id}"
            target_acc.historique += f"\n[{now}] Virement reçu: +{amount} FCFA de {source_id}"
            
            source_acc.save()
            target_acc.save()

            # Enregistrement dans le nouveau modèle Transaction
            Transaction.objects.create(
                sender_acc=source_acc,
                receiver_acc=target_acc,
                amount=amount,
                transaction_type='transfert',
                description=f"Virement P2P de {source_acc.titulaire} vers {target_acc.titulaire}"
            )

            messages.success(request, f"Virement de {amount} FCFA vers {target_id} effectué !")

    return redirect('data')

@login_required
def update_balance(request, account_id):
    """Permet aux admins de définir le capital d'un utilisateur"""
    # Règle 10 : Tentative de modification non autorisée
    if not is_admin(request.user):
        try:
            rule_r10 = SecurityRule.objects.get(code='unauthorized_mod')
            if rule_r10.is_active:
                acc = CompteBancaire.objects.filter(id=account_id).first()
                unauthorized_modification.send(
                    sender=None, 
                    username=request.user.username,
                    ip=request.META.get('REMOTE_ADDR'),
                    target_account=acc.id_compte if acc else account_id
                )
        except:
            pass
        messages.error(request, "Accès refusé.")
        return redirect('data')

    if request.method == 'POST':
        account = get_object_or_404(CompteBancaire, id=account_id)
        try:
            new_balance = Decimal(request.POST.get('new_balance'))
            old_balance = account.solde
            account.solde = new_balance
            now = timezone.now().strftime("%d/%m/%Y %H:%M")
            account.historique += f"\n[{now}] Ajustement Admin: {old_balance} -> {new_balance} FCFA"
            account.save()

            # Enregistrement dans le nouveau modèle Transaction
            diff = new_balance - old_balance
            if diff != 0:
                abs_diff = abs(diff)
                if diff > 0:
                    # Augmentation (Crédit Admin)
                    Transaction.objects.create(
                        sender_acc=None,
                        receiver_acc=account,
                        amount=abs_diff,
                        transaction_type='ajustement',
                        description=f"Crédit administratif par {request.user.username}"
                    )
                else:
                    # Diminution (Débit Admin)
                    Transaction.objects.create(
                        sender_acc=account,
                        receiver_acc=None,
                        amount=abs_diff,
                        transaction_type='ajustement',
                        description=f"Débit administratif par {request.user.username}"
                    )
            
            messages.success(request, f"Capital de {account.titulaire} mis à jour.")
        except (ValueError, TypeError, InvalidOperation):
            messages.error(request, "Montant invalide.")
    return redirect('data')

@login_required
def create_account_view(request):
    """Permet à un utilisateur de se créer un compte bancaire avec 0 FCFA"""
    if request.method == 'POST':
        # Générer un ID unique: SDM-XXX-XYZ
        while True:
            parts = [
                "".join(random.choices(string.digits, k=3)),
                "".join(random.choices(string.ascii_uppercase, k=3))
            ]
            new_id = f"SDM-{parts[0]}-{parts[1]}"
            if not CompteBancaire.objects.filter(id_compte=new_id).exists():
                break
        
        # Création du compte
        CompteBancaire.objects.create(
            id_compte=new_id,
            titulaire=request.user.username,
            solde=0.00,
            owner=request.user,
            classification='confidentiel',
            historique=f"[{timezone.now().strftime('%d/%m/%Y %H:%M')}] Ouverture de compte initialisée."
        )
        messages.success(request, f"Votre nouveau compte {new_id} a été crée avec succès ! Contactez un admin pour définir votre capital.")
        
    return redirect('data')

@login_required
def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
@user_passes_test(is_admin)
def users_manage_view(request):
    """Vue de gestion des utilisateurs pour l'administrateur"""
    users = CustomUser.objects.all().order_by('-date_joined')
    stats = {
        'total': users.count(),
        'locked': users.filter(is_locked=True).count(),
        'admins': users.filter(role='admin').count(),
    }
    return render(request, 'core/users_manage.html', {'users': users, 'stats': stats})

@login_required
@user_passes_test(is_admin)
def toggle_user_lock(request, user_id):
    """Bascule l'état de verrouillage d'un utilisateur"""
    user_to_mod = get_object_or_404(CustomUser, id=user_id)
    if not user_to_mod.is_superuser: # Sécurité: on ne bloque pas un superadmin
        user_to_mod.is_locked = not user_to_mod.is_locked
        user_to_mod.save()
        messages.info(request, f"Statut de {user_to_mod.username} mis à jour.")
    return redirect('users_manage')

@login_required
def history_view(request):
    """Affiche l'historique des transactions. Analystes interdits."""
    if request.user.role == 'analyste' and not request.user.is_superuser:
        messages.warning(request, "Accès refusé à l'historique financier.")
        return redirect('security_dashboard')

    if request.user.role == 'admin' or request.user.is_superuser:
        # L'admin voit TOUT
        transactions = Transaction.objects.all().select_related('sender_acc', 'receiver_acc')
    else:
        # L'utilisateur voit ses envois ET ses réceptions
        # On récupère tous les comptes appartenant à l'utilisateur
        my_accounts = request.user.comptes.all()
        from django.db.models import Q
        transactions = Transaction.objects.filter(
            Q(sender_acc__in=my_accounts) | Q(receiver_acc__in=my_accounts)
        ).select_related('sender_acc', 'receiver_acc')

    return render(request, 'core/history.html', {'transactions': transactions})

@login_required
@user_passes_test(is_admin)
def change_user_role(request, user_id):
    """Change le rôle d'un utilisateur"""
    if request.method == 'POST':
        user_to_mod = get_object_or_404(CustomUser, id=user_id)
        new_role = request.POST.get('role')
        if new_role in dict(CustomUser.ROLE_CHOICES) and not user_to_mod.is_superuser:
            user_to_mod.role = new_role
            user_to_mod.save()
            messages.success(request, f"Rôle de {user_to_mod.username} changé en {user_to_mod.get_role_display()}.")
    return redirect('users_manage')

@login_required
@user_passes_test(is_admin)
def user_create_view(request):
    """Vue pour qu'un admin crée un nouvel utilisateur"""
    if request.method == 'POST':
        form = UserAdminCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Utilisateur créé avec succès.")
            return redirect('users_manage')
        else:
            messages.error(request, "Erreur lors de la création de l'utilisateur.")
    else:
        form = UserAdminCreationForm()
    return render(request, 'core/user_form.html', {'form': form, 'title': 'Nouvel Utilisateur'})

@login_required
@user_passes_test(is_admin)
def user_edit_view(request, user_id):
    """Vue pour qu'un admin modifie un utilisateur existant"""
    target_user = get_object_or_404(CustomUser, id=user_id)
    if target_user.is_superuser:
        messages.error(request, "Modification de super-utilisateur impossible via ce formulaire.")
        return redirect('users_manage')
        
    if request.method == 'POST':
        form = UserAdminEditForm(request.POST, instance=target_user)
        if form.is_valid():
            form.save()
            messages.success(request, f"Utilisateur {target_user.username} mis à jour.")
            return redirect('users_manage')
        else:
            messages.error(request, "Erreur lors de la mise à jour.")
    else:
        form = UserAdminEditForm(instance=target_user)
    return render(request, 'core/user_form.html', {'form': form, 'title': f'Modifier {target_user.username}'})

@login_required
@user_passes_test(is_admin)
def user_detail_view(request, user_id):
    """Fiche détaillée d'un utilisateur pour l'admin"""
    target_user = get_object_or_404(CustomUser, id=user_id)
    user_events = SecurityEvent.objects.filter(username=target_user.username).order_by('-timestamp')[:50]
    user_comptes = CompteBancaire.objects.filter(owner=target_user)
    
    return render(request, 'core/user_detail.html', {
        'target_user': target_user,
        'events': user_events,
        'comptes': user_comptes
    })
