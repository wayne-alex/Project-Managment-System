from django.contrib import admin

from organization.models import SubscriptionPackage, Organization, OrganizationMember, AuditLog

# Register your models here.
admin.site.register(SubscriptionPackage)
admin.site.register(Organization)
admin.site.register(OrganizationMember)
admin.site.register(AuditLog)