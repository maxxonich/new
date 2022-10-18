from django.contrib import admin
from .models import Product, Category, Company, ProductSize, ProductSite, Comment
# admin.register() decorator
from .models import Image

admin.site.register(Image)


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('pk', 'name', 'content',)
    list_filter = ('category',)
    search_fields = ('name', 'content')


admin.site.register(Category)
admin.site.register(Company)
admin.site.register(ProductSize)
admin.site.register(ProductSite)
admin.site.register(Comment)
