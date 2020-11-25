import cv2
from time import sleep
from PIL import Image as im
import os

def get_frames(filename):

    video_object = cv2.VideoCapture(filename)
    count, succ = 0, 1

    while succ:
        """Extracting frames.
           set 'count * 1000' value as suited by the movie.
           for drama films change to 3000.
           for action leave unchanged"""

        succ, image = video_object.read()
        video_object.set(cv2.CAP_PROP_POS_MSEC, (count * 1000))
        cv2.imwrite(f"frame{count}", image)
        print(f"frame {count} saved")
        try:
            foo = im.open("frame{}.jpg".format(count))
            foo.save("frame{}.jpg".format(count), optimize = True, quality = 50)
        except:
            pass
    count += 1

if __name__ == "__main__":
    get_frames(filename = 'outfile.mp4')