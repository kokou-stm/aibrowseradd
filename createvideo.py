import os
from PIL import Image
import cv2

#print(os.listdir("/var/folders/80/dm2xwwgx2zq1qb7dtk389v9w0000gn/T/browser_use_agent_06927692-b4f1-7bac-8000-fe25bf9479fd_1764190507/screenshots"))


# Chemin vers ton dossier d'images
image_folder = "/var/folders/80/dm2xwwgx2zq1qb7dtk389v9w0000gn/T/browser_use_agent_06927692-b4f1-7bac-8000-fe25bf9479fd_1764190507/screenshots"

# Récupérer et trier les fichiers d'image
images = [img for img in os.listdir(image_folder) if img.endswith((".png", ".jpg", ".jpeg"))]
images.sort()  # Assure l'ordre correct
print(images)

# Lire la première image pour obtenir la taille
frame = cv2.imread(os.path.join(image_folder, images[0]))
height, width, layers = frame.shape


# Définir le codec pour MP4 et créer l'objet VideoWriter
video = cv2.VideoWriter("output_video.mp4", cv2.VideoWriter_fourcc(*"mp4v"), 5, (width, height))



for image in images:
    frame = cv2.imread(os.path.join(image_folder, image))
    video.write(frame)
    video.write(frame)

# Libérer les ressources
video.release()
cv2.destroyAllWindows()




ID_CLIENT= "415285702040-c4p0is1l5jh1dbc31mojepmfmoudo4bm.apps.googleusercontent.com"