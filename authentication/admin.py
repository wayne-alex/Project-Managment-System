from django.contrib import admin

from authentication.models import User, RefreshTokenRecord, PasswordResetToken

# Register your models here.
admin.register(User)
admin.register(RefreshTokenRecord)
admin.register(PasswordResetToken)