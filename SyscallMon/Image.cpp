#include <Windows.h>

#include <Gdiplus.h>
#pragma comment(lib,"Gdiplus.lib")

#include <shellapi.h>

#include <QIcon>
#include <QImage>
#include <QPixmap>

class GdiPlusInit
{
public:
	Gdiplus::GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	GdiPlusInit()
	{
		Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
	}
	~GdiPlusInit()
	{
		Gdiplus::GdiplusShutdown(gdiplusToken);
	}
};

GdiPlusInit Instance;

/*int GetEncoderClsid(LPCWSTR format, CLSID *pClsid)
{
	UINT     num = 0;
	UINT     size = 0;

	Gdiplus::ImageCodecInfo*   pImageCodecInfo = NULL;

	Gdiplus::GetImageEncodersSize(&num, &size);
	if (size == 0)
		return   -1;     //   Failure 

	pImageCodecInfo = (Gdiplus::ImageCodecInfo*)malloc(size);
	if (pImageCodecInfo == NULL)
		return   -1;     //   Failure 

	GetImageEncoders(num, size, pImageCodecInfo);

	for (UINT j = 0; j < num; ++j)
	{
		if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0)
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			return   j;     //   Success 
		}
	}

	free(pImageCodecInfo);
	return   -1;     //   Failure 
}

Gdiplus::Bitmap* ScaleImage(Gdiplus::Bitmap *source, int width, int height)
{
	Gdiplus::Rect zoomRect(0, 0, width, height);
	Gdiplus::Bitmap* pImageScale = new Gdiplus::Bitmap(zoomRect.Width, zoomRect.Height, PixelFormat32bppARGB);
	Gdiplus::Graphics graphicsScale(pImageScale);
	Gdiplus::TextureBrush brush(source);
	graphicsScale.ScaleTransform((Gdiplus::REAL)((Gdiplus::REAL)zoomRect.Width / (Gdiplus::REAL)source->GetWidth()),
		(Gdiplus::REAL)((Gdiplus::REAL)zoomRect.Height / (Gdiplus::REAL)source->GetHeight()));
	graphicsScale.FillRectangle(&brush, zoomRect);
	return pImageScale;
}*/

HICON GetIconFromFile(LPCTSTR szImageFileName)
{
    SHFILEINFO sfi;
	if (SUCCEEDED(SHGetFileInfo(szImageFileName, FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_LARGEICON | SHGFI_ICON | SHGFI_USEFILEATTRIBUTES)))
	{
		if (sfi.hIcon)
		{
			return sfi.hIcon;
		}
    }

	return NULL;
}

static QImage qt_fromWinHBITMAP(HDC hdc, HBITMAP bitmap, int w, int h)
{
    BITMAPINFO bmi;
    memset(&bmi, 0, sizeof(bmi));
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = w;
    bmi.bmiHeader.biHeight      = -h;
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    bmi.bmiHeader.biSizeImage   = w * h * 4;

    QImage image(w, h, QImage::Format_ARGB32_Premultiplied);
    if (image.isNull())
        return image;

    // Get bitmap bits
    uchar *data = (uchar *) malloc(bmi.bmiHeader.biSizeImage);

    if (GetDIBits(hdc, bitmap, 0, h, data, &bmi, DIB_RGB_COLORS)) {
        // Create image and copy data into image.
        for (int y=0; y<h; ++y) {
            void *dest = (void *) image.scanLine(y);
            void *src = data + y * image.bytesPerLine();
            memcpy(dest, src, image.bytesPerLine());
        }
    } else {
        qWarning("qt_fromWinHBITMAP(), failed to get bitmap bits");
    }
    free(data);

    return image;
}

QPixmap qt_fromHICON(HICON icon)//qt4.7 QPixmap::fromWinHICON(hIcon)
{
    bool foundAlpha = false;
    HDC screenDevice = GetDC(0);
    HDC hdc = CreateCompatibleDC(screenDevice);
    ReleaseDC(0, screenDevice);

    ICONINFO iconinfo;
    bool result = GetIconInfo(icon, &iconinfo); //x and y Hotspot describes the icon center
    if (!result)
        qWarning("QPixmap::fromWinHICON(), failed to GetIconInfo()");

    int w = iconinfo.xHotspot * 2;
    int h = iconinfo.yHotspot * 2;

    BITMAPINFOHEADER bitmapInfo;
    bitmapInfo.biSize        = sizeof(BITMAPINFOHEADER);
    bitmapInfo.biWidth       = w;
    bitmapInfo.biHeight      = h;
    bitmapInfo.biPlanes      = 1;
    bitmapInfo.biBitCount    = 32;
    bitmapInfo.biCompression = BI_RGB;
    bitmapInfo.biSizeImage   = 0;
    bitmapInfo.biXPelsPerMeter = 0;
    bitmapInfo.biYPelsPerMeter = 0;
    bitmapInfo.biClrUsed       = 0;
    bitmapInfo.biClrImportant  = 0;
    DWORD* bits;

    HBITMAP winBitmap = CreateDIBSection(hdc, (BITMAPINFO*)&bitmapInfo, DIB_RGB_COLORS, (VOID**)&bits, NULL, 0);
    HGDIOBJ oldhdc = (HBITMAP)SelectObject(hdc, winBitmap);
    DrawIconEx( hdc, 0, 0, icon, iconinfo.xHotspot * 2, iconinfo.yHotspot * 2, 0, 0, DI_NORMAL);
    QImage image = qt_fromWinHBITMAP(hdc, winBitmap, w, h);

    for (int y = 0 ; y < h && !foundAlpha ; y++) {
        QRgb *scanLine= reinterpret_cast<QRgb *>(image.scanLine(y));
        for (int x = 0; x < w ; x++) {
            if (qAlpha(scanLine[x]) != 0) {
                foundAlpha = true;
                break;
            }
        }
    }
    if (!foundAlpha) {
        //If no alpha was found, we use the mask to set alpha values
        DrawIconEx( hdc, 0, 0, icon, w, h, 0, 0, DI_MASK);
        QImage mask = qt_fromWinHBITMAP(hdc, winBitmap, w, h);

        for (int y = 0 ; y < h ; y++){
            QRgb *scanlineImage = reinterpret_cast<QRgb *>(image.scanLine(y));
            QRgb *scanlineMask = mask.isNull() ? 0 : reinterpret_cast<QRgb *>(mask.scanLine(y));
            for (int x = 0; x < w ; x++){
                if (scanlineMask && qRed(scanlineMask[x]) != 0)
                    scanlineImage[x] = 0; //mask out this pixel
                else
                    scanlineImage[x] |= 0xff000000; // set the alpha channel to 255
            }
        }
    }
    //dispose resources created by iconinfo call
    DeleteObject(iconinfo.hbmMask);
    DeleteObject(iconinfo.hbmColor);

    SelectObject(hdc, oldhdc); //restore state
    DeleteObject(winBitmap);
    DeleteDC(hdc);
    return QPixmap::fromImage(image);
}
