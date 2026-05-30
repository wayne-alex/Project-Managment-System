import json

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.db.models import Model
from django.http import JsonResponse
from django.shortcuts import render, redirect

from organization.models import Organization, OrganizationMember, SubscriptionPackage
from .models import User


# Create your views here.
def login_user(request):
    if request.user.is_authenticated:
        org_id = OrganizationMember.objects.filter(user=request.user).values_list('org__id', flat=True).first()

        if org_id:
            return redirect("organization:workspace", org_id=org_id)

        # Fallback: User is authenticated but orphanized (no workspace records found)
        return render(request, "errors/workspace_orphaned.html", status=403)

    if request.method == "POST":
        body = json.loads(request.body)
        email = body.get("email", "").strip().lower()
        password = body.get("password", "")
        remember = body.get("remember", False)

        user = authenticate(request, username=email, password=password)

        if user is None:
            return JsonResponse({"success": False, "message": "Invalid email or password."}, status=401)

        if not user.is_active:
            return JsonResponse({"success": False, "message": "Your account is inactive."}, status=403)

        login(request, user)
        org = OrganizationMember.objects.get(user=user)
        request.session.set_expiry(60 * 60 * 24 * 30 if remember else 0)

        return JsonResponse({
            "success": True,
            "message": f"Welcome back, {user.first_name}!",
            "redirect": f"/org/workspace/{org.id}/",
        })

    return render(request, "login.html")


def register(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"success": False, "message": "Invalid request."}, status=400)

        name = body.get("name", "").strip()
        first_name = body.get("first_name", "").strip()
        last_name = body.get("last_name", "").strip()
        email = body.get("email", "").strip().lower()
        password = body.get("password", "")
        country = body.get("country", "")
        plan = body.get("plan", "free")

        # Basic validation
        if not all([name, first_name, last_name, email, password]):
            return JsonResponse({"success": False, "message": "All fields are required."}, status=400)

        if len(password) < 8:
            return JsonResponse({"success": False, "message": "Password must be at least 8 characters."}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({"success": False, "message": "An account with this email already exists."}, status=400)

        if plan not in ["free", "pro", "enterprise"]:
            plan = "free"

        # Save to session — org is created in step 2
        request.session["reg_step1"] = {
            "org_name": name,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": password,
            "country": country,
            "plan": plan,
        }

        return JsonResponse({
            "success": True,
            "message": "Step 1 complete!",
            "redirect": "/auth/workspace/",
        })

    return render(request, 'register.html')


def workspace(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

        # Guard: must have completed step 1
    if "reg_step1" not in request.session:
        return redirect("register")

    if request.method == "POST":
        step1 = request.session.get("reg_step1", {})

        timezone = request.POST.get("timezone", "UTC")
        currency = request.POST.get("currency", "USD")
        logo = request.FILES.get("logo")

        try:
            modules = json.loads(request.POST.get("modules", "[]"))
        except (json.JSONDecodeError, TypeError):
            modules = []

        # Extract email domain for tenant isolation
        email = step1.get("email", "")
        domain = email.split("@")[-1] if "@" in email else None

        # Check domain uniqueness
        if domain and Organization.objects.filter(domain=domain).exists():
            return JsonResponse({
                "success": False,
                "message": f"An organization with the domain '{domain}' already exists.",
            }, status=400)
        package = SubscriptionPackage.objects.get(name= step1["plan"])

        # Create Organization
        org = Organization.objects.create(
            name=step1["org_name"],
            domain=domain,
            package =package,
            timezone=timezone,
            logo=logo,
        )

        # Create User (admin of this org)
        user = User.objects.create_user(
            email=email,
            password=step1["password"],
            first_name=step1["first_name"],
            last_name=step1["last_name"],
            role="admin",
            is_verified=False,
        )

        # Link user to org as admin
        OrganizationMember.objects.create(
            user=user,
            org=org,
            role="admin",
        )

        # Clean up session
        del request.session["reg_step1"]

        # Log them in immediately
        login(request, user)

        return JsonResponse({
            "success": True,
            "message": f"Workspace '{org.name}' is live!",
            "redirect": f"/org/workspace/{org.id}/",
        })

    return render(request, 'workspace.html')


def workspaceAdmin(request):
    return render(request, 'workspace_admin.html')


def forgotpassword(request):
    return render(request, 'forgotpassword.html')


def changepassword(request):
    token_validated = False
    return render(request, 'changepassword.html', {"token_validated": token_validated})


def dataseparationact(request):
    return render(request, 'DataSeparationAct.html')


def landing(request):
    plans = SubscriptionPackage.objects.all()
    return render(request, 'landingPage.html', {"plans": plans})

def logout_user(request):
    """
    Flushes the user's authenticated session state and redirects
    them cleanly back to the system landing page.
    """
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect("authentication:login")