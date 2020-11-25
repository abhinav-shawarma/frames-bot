#!/usr/bin/bash
echo "Write subtitle (srt file) and movie file names separated by space"
read subtitle movie
ffmpeg -i $subtitle sub.ass
echo "Writing subtitles"
ffmpeg -i $movie -vf ass=sub.ass outfile.mp4