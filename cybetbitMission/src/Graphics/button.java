package Graphics;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;

public class button extends JButton{
	private static final long serialVersionUID = 1L;
	private ImageIcon image;
	public button(String image,String rolloverImage){
		setIcon(new ImageIcon(this.getClass().getResource(image)));
		setRolloverIcon(new ImageIcon(this.getClass().getResource(rolloverImage)));
		setDisabledIcon(new ImageIcon(this.getClass().getResource(rolloverImage)));
		setBorder(BorderFactory.createEmptyBorder());
		setContentAreaFilled(false);
		this.image = new ImageIcon(this.getClass().getResource(image));
	}
	public int getWidth(){
		return image.getIconWidth();
	}
	public int getHeight(){
		return image.getIconHeight();
	}
}
