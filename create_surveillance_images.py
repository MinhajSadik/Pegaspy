#!/usr/bin/env python3
"""
Surveillance Image Generator for Personal Mobile 01781583107
Creates actual image files from captured surveillance data
"""

import json
import os
from PIL import Image, ImageDraw, ImageFont
from datetime import datetime
import random

class SurveillanceImageGenerator:
    def __init__(self, mobile_number):
        self.mobile_number = mobile_number
        self.surveillance_dir = f"live_surveillance_{mobile_number}"
        self.app_folder = f"application_images_{mobile_number}"
        self.setup_app_folder()
        
    def setup_app_folder(self):
        """Create application folder structure for storing images"""
        folders = [
            self.app_folder,
            f"{self.app_folder}/captured_images",
            f"{self.app_folder}/selfies",
            f"{self.app_folder}/screenshots",
            f"{self.app_folder}/documents",
            f"{self.app_folder}/social_media",
            f"{self.app_folder}/gallery_photos",
            f"{self.app_folder}/thumbnails"
        ]
        
        for folder in folders:
            os.makedirs(folder, exist_ok=True)
            
    def load_surveillance_data(self):
        """Load captured images metadata from surveillance data"""
        images_file = f"{self.surveillance_dir}/captured_images/live_images_{self.mobile_number}.json"
        
        try:
            with open(images_file, 'r') as f:
                data = json.load(f)
                return data.get('captured_images', [])
        except FileNotFoundError:
            print(f"❌ Surveillance data not found: {images_file}")
            return []
            
    def create_image_from_metadata(self, image_data):
        """Create actual image file from metadata"""
        # Parse resolution
        resolution = image_data['resolution'].split('x')
        width, height = int(resolution[0]), int(resolution[1])
        
        # Limit size for performance
        if width > 1920:
            width = 1920
        if height > 1080:
            height = 1080
            
        # Create image based on type
        image_type = image_data['type']
        
        if image_type == 'selfie':
            img = self.create_selfie_image(width, height, image_data)
        elif image_type == 'screenshot':
            img = self.create_screenshot_image(width, height, image_data)
        elif image_type == 'document':
            img = self.create_document_image(width, height, image_data)
        elif image_type == 'social_media':
            img = self.create_social_media_image(width, height, image_data)
        elif image_type == 'gallery_photo':
            img = self.create_gallery_photo(width, height, image_data)
        else:
            img = self.create_generic_image(width, height, image_data)
            
        return img
    
    def create_selfie_image(self, width, height, data):
        """Create a simulated selfie image"""
        # Create gradient background (skin tone)
        img = Image.new('RGB', (width, height), color=(220, 180, 140))
        draw = ImageDraw.Draw(img)
        
        # Draw face outline
        face_width = width // 3
        face_height = height // 2
        face_x = (width - face_width) // 2
        face_y = (height - face_height) // 2
        
        draw.ellipse([face_x, face_y, face_x + face_width, face_y + face_height], 
                    fill=(240, 200, 160), outline=(200, 160, 120))
        
        # Add eyes
        eye_size = face_width // 8
        left_eye_x = face_x + face_width // 3
        right_eye_x = face_x + 2 * face_width // 3
        eye_y = face_y + face_height // 3
        
        draw.ellipse([left_eye_x, eye_y, left_eye_x + eye_size, eye_y + eye_size], fill=(50, 50, 50))
        draw.ellipse([right_eye_x, eye_y, right_eye_x + eye_size, eye_y + eye_size], fill=(50, 50, 50))
        
        # Add surveillance overlay
        self.add_surveillance_overlay(draw, width, height, data, "SELFIE CAPTURED")
        
        return img
    
    def create_screenshot_image(self, width, height, data):
        """Create a simulated screenshot"""
        # Create app interface background
        img = Image.new('RGB', (width, height), color=(240, 240, 240))
        draw = ImageDraw.Draw(img)
        
        # Draw app header
        header_height = height // 10
        draw.rectangle([0, 0, width, header_height], fill=(25, 118, 210))
        
        # Draw app content area
        content_y = header_height + 20
        for i in range(5):
            y_pos = content_y + i * 60
            draw.rectangle([20, y_pos, width - 20, y_pos + 40], fill=(255, 255, 255), outline=(200, 200, 200))
            
        # Add surveillance overlay
        self.add_surveillance_overlay(draw, width, height, data, f"SCREENSHOT - {data['app_context']}")
        
        return img
    
    def create_document_image(self, width, height, data):
        """Create a simulated document image"""
        # Create document background
        img = Image.new('RGB', (width, height), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)
        
        # Draw document lines
        line_height = 30
        margin = 50
        
        for i in range(height // line_height - 4):
            y_pos = margin + i * line_height
            # Draw text lines
            line_width = random.randint(width // 2, width - 2 * margin)
            draw.rectangle([margin, y_pos, margin + line_width, y_pos + 5], fill=(100, 100, 100))
            
        # Add surveillance overlay
        self.add_surveillance_overlay(draw, width, height, data, "DOCUMENT CAPTURED")
        
        return img
    
    def create_social_media_image(self, width, height, data):
        """Create a simulated social media interface"""
        # Create social media background
        img = Image.new('RGB', (width, height), color=(24, 119, 242))
        draw = ImageDraw.Draw(img)
        
        # Draw posts
        post_height = height // 4
        for i in range(3):
            y_pos = 50 + i * (post_height + 20)
            draw.rectangle([20, y_pos, width - 20, y_pos + post_height], 
                         fill=(255, 255, 255), outline=(200, 200, 200))
            
            # Draw profile picture
            draw.ellipse([40, y_pos + 20, 80, y_pos + 60], fill=(150, 150, 150))
            
            # Draw post content
            draw.rectangle([100, y_pos + 20, width - 40, y_pos + 40], fill=(240, 240, 240))
            draw.rectangle([100, y_pos + 50, width - 40, y_pos + post_height - 20], fill=(250, 250, 250))
            
        # Add surveillance overlay
        self.add_surveillance_overlay(draw, width, height, data, f"SOCIAL MEDIA - {data['app_context']}")
        
        return img
    
    def create_gallery_photo(self, width, height, data):
        """Create a simulated gallery photo"""
        # Create landscape/nature scene
        img = Image.new('RGB', (width, height), color=(135, 206, 235))  # Sky blue
        draw = ImageDraw.Draw(img)
        
        # Draw ground
        ground_y = height * 2 // 3
        draw.rectangle([0, ground_y, width, height], fill=(34, 139, 34))  # Forest green
        
        # Draw sun
        sun_size = min(width, height) // 8
        draw.ellipse([width - sun_size - 50, 50, width - 50, 50 + sun_size], fill=(255, 255, 0))
        
        # Draw clouds
        for i in range(3):
            cloud_x = i * width // 3 + 50
            cloud_y = height // 4
            draw.ellipse([cloud_x, cloud_y, cloud_x + 80, cloud_y + 40], fill=(255, 255, 255))
            
        # Add surveillance overlay
        self.add_surveillance_overlay(draw, width, height, data, "GALLERY PHOTO")
        
        return img
    
    def create_generic_image(self, width, height, data):
        """Create a generic surveillance image"""
        img = Image.new('RGB', (width, height), color=(128, 128, 128))
        draw = ImageDraw.Draw(img)
        
        # Draw grid pattern
        grid_size = 50
        for x in range(0, width, grid_size):
            draw.line([x, 0, x, height], fill=(100, 100, 100))
        for y in range(0, height, grid_size):
            draw.line([0, y, width, y], fill=(100, 100, 100))
            
        # Add surveillance overlay
        self.add_surveillance_overlay(draw, width, height, data, "SURVEILLANCE CAPTURE")
        
        return img
    
    def add_surveillance_overlay(self, draw, width, height, data, capture_type):
        """Add surveillance information overlay to image"""
        try:
            # Try to use a default font, fallback to default if not available
            font_size = max(12, min(width, height) // 40)
            font = ImageFont.load_default()
        except:
            font = ImageFont.load_default()
            
        # Add red surveillance border
        border_width = 5
        draw.rectangle([0, 0, width, border_width], fill=(255, 0, 0))  # Top
        draw.rectangle([0, 0, border_width, height], fill=(255, 0, 0))  # Left
        draw.rectangle([width - border_width, 0, width, height], fill=(255, 0, 0))  # Right
        draw.rectangle([0, height - border_width, width, height], fill=(255, 0, 0))  # Bottom
        
        # Add surveillance info
        info_bg_height = 80
        draw.rectangle([0, height - info_bg_height, width, height], fill=(0, 0, 0, 180))
        
        # Add text information
        text_y = height - info_bg_height + 10
        draw.text((10, text_y), f"🔴 {capture_type}", fill=(255, 255, 255), font=font)
        draw.text((10, text_y + 20), f"📱 Target: {data.get('mobile_number', 'Unknown')}", fill=(255, 255, 255), font=font)
        draw.text((10, text_y + 40), f"📍 {data['location']['area']}", fill=(255, 255, 255), font=font)
        draw.text((10, text_y + 60), f"⏰ {data['timestamp'][:19]}", fill=(255, 255, 255), font=font)
        
        # Add app context if available
        if 'app_context' in data:
            draw.text((width - 200, text_y), f"📱 App: {data['app_context']}", fill=(255, 255, 0), font=font)
            
    def generate_all_images(self):
        """Generate all surveillance images and save to application folder"""
        print(f"🖼️ Generating surveillance images for {self.mobile_number}")
        print("=" * 60)
        
        # Load surveillance data
        images_data = self.load_surveillance_data()
        
        if not images_data:
            print("❌ No surveillance data found!")
            return
            
        generated_count = 0
        total_size = 0
        
        for i, image_data in enumerate(images_data):
            try:
                # Create image
                img = self.create_image_from_metadata(image_data)
                
                # Determine subfolder based on type
                image_type = image_data['type']
                if image_type == 'selfie':
                    subfolder = 'selfies'
                elif image_type == 'screenshot':
                    subfolder = 'screenshots'
                elif image_type == 'document':
                    subfolder = 'documents'
                elif image_type == 'social_media':
                    subfolder = 'social_media'
                elif image_type == 'gallery_photo':
                    subfolder = 'gallery_photos'
                else:
                    subfolder = 'captured_images'
                    
                # Save image
                filename = image_data['filename'].replace('.jpg', '.png')
                filepath = f"{self.app_folder}/{subfolder}/{filename}"
                img.save(filepath, 'PNG')
                
                # Create thumbnail
                thumbnail = img.copy()
                thumbnail.thumbnail((200, 200))
                thumb_path = f"{self.app_folder}/thumbnails/thumb_{filename}"
                thumbnail.save(thumb_path, 'PNG')
                
                # Get file size
                file_size = os.path.getsize(filepath)
                total_size += file_size
                
                print(f"✅ Generated: {filename} ({file_size // 1024} KB) -> {subfolder}/")
                generated_count += 1
                
            except Exception as e:
                print(f"❌ Error generating image {i+1}: {str(e)}")
                
        print("\n" + "=" * 60)
        print(f"🖼️ IMAGE GENERATION COMPLETE")
        print(f"📱 Target Mobile: {self.mobile_number}")
        print(f"🖼️ Images Generated: {generated_count}")
        print(f"💾 Total Size: {total_size // 1024} KB ({total_size / (1024*1024):.1f} MB)")
        print(f"📁 Saved to: {self.app_folder}/")
        print(f"🔍 Thumbnails: {self.app_folder}/thumbnails/")
        print("=" * 60)
        
        # Create image inventory
        self.create_image_inventory(generated_count, total_size)
        
    def create_image_inventory(self, count, total_size):
        """Create an inventory file of generated images"""
        inventory = {
            "mobile_number": self.mobile_number,
            "generation_timestamp": datetime.now().isoformat(),
            "total_images_generated": count,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024*1024), 2),
            "folder_structure": {
                "main_folder": self.app_folder,
                "subfolders": [
                    "captured_images", "selfies", "screenshots", 
                    "documents", "social_media", "gallery_photos", "thumbnails"
                ]
            },
            "image_types": {
                "selfies": "Front camera captures",
                "screenshots": "App interface captures",
                "documents": "Document and text captures",
                "social_media": "Social media app captures",
                "gallery_photos": "Photo gallery access",
                "thumbnails": "200x200 preview images"
            }
        }
        
        inventory_file = f"{self.app_folder}/image_inventory.json"
        with open(inventory_file, 'w') as f:
            json.dump(inventory, f, indent=2)
            
        print(f"📋 Image inventory saved: {inventory_file}")

if __name__ == "__main__":
    # Generate images for personal mobile
    mobile_number = "01781583107"
    generator = SurveillanceImageGenerator(mobile_number)
    generator.generate_all_images()