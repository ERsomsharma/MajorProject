from django.contrib import admin
from .models import Product, Variation, ReviewRating

# Register your models here.

class ProductAdmin(admin.ModelAdmin):
    list_display = ('product_name', 'price', 'stock', 'category','is_available', 'created_date', 'modified_date')
    prepopulated_fields = {'slug': ('product_name',)}

admin.site.register(Product, ProductAdmin)

class VariationAdmin(admin.ModelAdmin):
    list_display = ('product', 'variation_category', 'variation_value', 'is_active', 'created_date')
    list_filter = ('product', 'variation_category','variation_value' ,'is_active')
    list_editable = ('is_active',)
admin.site.register(Variation, VariationAdmin)

class ReviewRatingAdmin(admin.ModelAdmin):
    list_display = ('product', 'user', 'subject', 'rating', 'status', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('product__product_name', 'user__first_name', 'subject', 'review')
    list_editable = ('status',)
admin.site.register(ReviewRating, ReviewRatingAdmin)