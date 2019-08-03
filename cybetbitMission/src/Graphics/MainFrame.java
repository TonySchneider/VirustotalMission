package Graphics;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JFrame;

public class MainFrame extends JFrame {
	private static final long serialVersionUID = 1L;
	private static MainFrame frame = null;
	private static Dimension frameSize;
	public MainFrame(String title){
		super(title);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setLayout(new BorderLayout(0,0));//set border layout for set 2 panels - one for the city background and one for the below buttons
		setResizable(false);
	}
	public static MainFrame getInstance(){
		if(frame == null)
			frame = new MainFrame("Cyberbit Mission");
		return frame;
	}
	public static void main(String[] args) {
		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();//get the screen size.
		MainFrame frame = MainFrame.getInstance();
		final MainPanel backgroundPanel = new MainPanel();

		frameSize = new Dimension(670,500);
		frame.add(backgroundPanel);
		frame.setPreferredSize(new Dimension(frameSize.width,(int)(frameSize.height)));//set size of the frame as the size of the background
		frame.setLocation(screenSize.width/2-frame.getPreferredSize().width/2, screenSize.height/2-frame.getPreferredSize().height/2);//set the frame in the middle of the screen
		
		frame.pack(); 
		frame.setVisible(true); 
		
	}
	
}
